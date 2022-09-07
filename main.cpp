#include <iostream>
using namespace std;
#include <string>
#include <queue>
#include <fstream>
#include <list>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <stdint.h>

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <bzlib.h>

#include <tclap/CmdLine.h>

#include <libs3.h>

#include "cryptopp/sha.h"
#include "cryptopp/hex.h"

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/files.h"
#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "assert.h"

typedef struct put_object_callback_data {
	
	ifstream * ifile;
	uint64_t contentLength;
	
} put_object_callback_data;

S3Status responsePropertiesCallback(const S3ResponseProperties * properties, void * callbackData)
{
	return S3StatusOK;
}

static void responseCompleteCallback(S3Status status, const S3ErrorDetails * error, void * callbackData)
{
	if (status!=S3StatusOK) {
		
		if (status==31) {
			
			cerr << "S3 endpoint URL was not specified correctly." << endl;
			cerr << "a valid endpoint looks like this:" << endl;
			cerr << "s3-us-west-2.amazonaws.com" << endl;
			cerr << "peace out" << endl;
			
		} else {
			
			cout << "S3 error:" << status << endl;
			cout << "S3 error furtherDetails:" << error->furtherDetails << endl;
			cout << "S3 error message:" << error->message << endl;

		}
		
	}
	
	return;
}

static int putObjectDataCallback(int bufferSize, char * buffer, void * callbackData);


int main(int argc, char **argv) {

	//parse command line options
	bool recurse=false, verbose=false, countChanges=false, fileChanges=false, forceAll=false;
	string password, bucket, accessKeyId, secretAccessKey, host;
	
	try {
		
		TCLAP::CmdLine cmd("cppbackup v0.1 - scans for file changes using SHA1 and then compresses, encrypts and transfers to amazon s3 for backup and archival purposes", ' ', "1.0");
		
		TCLAP::SwitchArg verboseSwitch("v","verbose","set high verbosity for debugging and testing purposes", cmd, false);

		TCLAP::SwitchArg fileChangesSwitch("f","file_changes","only show changed files. don't actually do any work", cmd, false);
		
		TCLAP::SwitchArg recurseSwitch("R","recurse","recursively scan directories", cmd, false);
		
		TCLAP::SwitchArg forceAllSwitch("g","forceall","force all files to be backed up and update all sha1 signatures in local database", cmd, false);
		
		TCLAP::SwitchArg encryptFilenamesSwitch("e","encryptfilenames","encrypt file names before sending to S3", cmd, false);
		
		TCLAP::ValueArg<std::string> passwordArg("p", "password", "set AES encryption password for file encryption", true, "", "password");//forced
		cmd.add( passwordArg );

		TCLAP::ValueArg<std::string> bucketArg("b", "bucket", "set amazon s3 bucket", true, "", "bucket");//forced
		cmd.add( bucketArg );
		
		TCLAP::ValueArg<std::string> accessKeyIdArg("a", "access_key_id", "set amazon s3 access key id - provided by amazon", true, "", "access key id");
		cmd.add( accessKeyIdArg );//forced

		TCLAP::ValueArg<std::string> secretAccessKeyArg("s", "secret_access_key", "set amazon s3 secret access key - provided by amazon", true, "", "secret access key");
		cmd.add( secretAccessKeyArg );//forced
		
		TCLAP::ValueArg<std::string> hostArg("u", "host", "set S3 server host", true, "", "S3 host");
		cmd.add( hostArg );//forced

		TCLAP::ValueArg<std::string> dbPathArg("d", "dbpath", "set alternative leveldb path - advanced usage only", false, "", "path");
		cmd.add( dbPathArg );

		TCLAP::ValueArg<std::string> systemIvArg("i", "systemiv", "set alternative system iv - advanced usage only", false, "", "iv");
		cmd.add( systemIvArg );
		
		cmd.parse( argc, argv );
		
		verbose=verboseSwitch.getValue();
		recurse=recurseSwitch.getValue();
		forceAll=forceAllSwitch.getValue();
		
		password=passwordArg.getValue();
		
		fileChanges=fileChangesSwitch.getValue();
		
		host=hostArg.getValue();
		bucket=bucketArg.getValue();
		accessKeyId=accessKeyIdArg.getValue();
		secretAccessKey=secretAccessKeyArg.getValue();
		
	} catch (TCLAP::ArgException & e) { 
		std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	}
	
	
	
	char h[1024];
	gethostname(h, 1024);
	
	string hostname=h;
	
  leveldb::Options options;
  options.create_if_missing = true;
	
	//system("rm -R ~/.ss3db/*");


	leveldb::DB* db;
  leveldb::Status status = leveldb::DB::Open(options, "~/.ss3db", &db);	
		
	if (!status.ok()) {
		cerr << "db - " << status.ToString() << endl;
		return 3;
	}	
	
	byte systemIv[ AES::BLOCKSIZE ];
	string systemIvReader;
	
	status=db->Get(leveldb::ReadOptions(), "system iv", &systemIvReader);
	if (status.ok()==true) {
		
		for(int t=0;t<systemIvReader.length();t++) {
			systemIv[t]=(byte)systemIvReader[t];
		}
		
	} else {
		
		if (status.IsNotFound()==true) {
			
			//generate system iv
			AutoSeededRandomPool prng;
			prng.GenerateBlock( systemIv, sizeof(systemIv) );
			
			for(int t=0;t<sizeof(systemIv);t++) {
				systemIvReader.append((char*)&systemIv[t]);
			}
			
			status=db->Put(leveldb::WriteOptions(), "system iv", systemIvReader);
			
			cout << "new system - creating system iv: " << systemIvReader << endl;
			
		} else {
			cerr << "error: " << status.ToString() << endl;
		}
		
	}
			
	
	struct dirent *entry=NULL;
  DIR *d=NULL;
	string * startPath=new string;
	*startPath=".";
  if(argc==2) {
    *startPath=argv[1];
  }
  
  //cout << "startPath: " << *startPath << endl;
	char actualpath [PATH_MAX+1];
	char *ptr;

	ptr = realpath(startPath->c_str(), actualpath);
	
	*startPath=actualpath;
	
	//cout << *startPath << endl;
	
	//return 0;
	
	struct stat statBuffer;
	
	bool topLevel=true, ss3BackupFound=false;
	int t=0;
	
	queue <string *> directories;
	queue <string *> files;
	
	directories.push(startPath);
	
	if (verbose==true) cout << endl;
	if (verbose==true) cout << "--find dirs and files--" << endl;
	
	while( directories.size()>0 ) {
	
		startPath=directories.front();
		directories.pop();
		
		d=opendir( startPath->c_str() );
		
		if(d==NULL) {
			
			cerr << "Couldn't open directory" << endl;
			
			delete startPath;
			
			break;
			
		}
		
		while(entry = readdir(d)) {
			
			string * combinedPath = new string;
			
			*combinedPath=*startPath+"/"+entry->d_name;
			
			//cout << *combinedPath;
			
			if (stat(combinedPath->c_str(), &statBuffer)!=0) {
				perror("stat");
				//return 2;
			}
			
			if ( (statBuffer.st_mode & S_IFMT)==S_IFDIR ) {
				
				//cout << " is a directory";
				
				string entryPath=entry->d_name;
				
				if (topLevel==true && entryPath==".ss3_temp_work") {
					
					ss3BackupFound=true;
					if (verbose==true) cout << "  found already existing .ss3_temp_work directory" << endl;

				} 
					
				if (recurse==true && entryPath!="." && entryPath!="..") {
					
					if (verbose==true) cout << "  directory paths:" << entryPath << "/" << endl;
					
					//we do this extra if, in case you ss3ed at a higher level directory and it still exists with random work files in it.
					if (entryPath!=".ss3_temp_work") {
						
						//cout << " added this directory to the queue" << endl;
						directories.push(combinedPath);
						
					}
					
				} else {
					//cout << endl;
				}
				
			} else if ( (statBuffer.st_mode & S_IFMT)==S_IFREG) {
				
				//cout << " is a file" << endl;
				files.push(combinedPath);
				
			} else {
				
				//cerr << " is not supported: " << entry->d_name << endl;
				
			}
				
		}
		
		delete startPath;

		t++;
		
		closedir(d);

	}
	
	if (ss3BackupFound==false) { 
		
		if (verbose==true && fileChanges==false) cout << "  creating .ss3_temp_work holder folder" << endl;
		if (fileChanges==false) mkdir(".ss3_temp_work", S_IRWXU | S_IRGRP | S_IWGRP);
		
	}
	
	if (verbose==true) cout << "--look for changes--" << endl;
	
	streampos size;
	byte * hashBuffer = new byte[4096];
	
	list <string *> compressFiles;
	
	while(files.size()>0) {
		
		string * filePath=files.front();
		files.pop();
		
		ifstream file (filePath->c_str(), ios::binary|ios::ate);
		if (file.is_open()) {
			
			size = file.tellg();
			
			//cout << "--file: " << *filePath << " size: " << size << endl;
			
			CryptoPP::SHA hash;
			byte digest[ CryptoPP::SHA::DIGESTSIZE ];
						
			file.seekg (0, ios::beg);
			t=0;
			
			while( t < size ) { 
				
				t+=file.readsome((char *)hashBuffer, 4096);
				hash.Update(hashBuffer, 4096);
				
			}
			
			file.close();
			
			hash.Final(digest);
			
			CryptoPP::HexEncoder encoder;
			string currentHash;
			encoder.Attach( new CryptoPP::StringSink( currentHash ) );
			encoder.Put( digest, sizeof(digest) );
			encoder.MessageEnd();			
			
			if (verbose==true) cout << "  ch: " << currentHash;
			
			string oldHash;
			
			status=db->Get(leveldb::ReadOptions(), *filePath+"-sig", &oldHash);
			if (status.ok()==true) {
				
				if (verbose==true) cout << " oh: " << oldHash << endl;
				
				if (oldHash!=currentHash || forceAll==true) {
					
					if (forceAll==true) {
					
						cout << "forced change" << endl;
						
					}
					
					compressFiles.push_back( filePath );
					
					leveldb::WriteBatch batch;
					batch.Delete(*filePath+"-sig");
					batch.Put(*filePath+"-sig", currentHash);
					status = db->Write(leveldb::WriteOptions(), &batch);					
					
				} else {
				
					delete filePath;
					
				}
				
			} else {
				
				if (verbose==true) cout << "oh: stored" << endl;
				
				if (status.IsNotFound()==true) {
					
					status=db->Put(leveldb::WriteOptions(), *filePath+"-sig", currentHash);
					
					if (verbose==true) cout << "changed: " << *filePath << endl;
					
					compressFiles.push_back( filePath );
					
				} else {
					cerr << "error: " << status.ToString() << endl;
				}
				
			}
			
		} else { 
			
			cerr << "Unable to open file" << endl;		
		
		}
		
	}
	
	delete hashBuffer;
	
	if ( compressFiles.size()>0 )	cout << "files that changed: " << compressFiles.size() << endl;
	
	if (fileChanges==true) {
		
		if ( compressFiles.size()>0 ) {
			
			cout << "list of files that have changed: " << endl;
			cout << endl;
			
			while(compressFiles.size()>0) { 
				
				string * filePath=compressFiles.front();
				compressFiles.pop_front();
				
				cout << "  " << *filePath << endl;
				
				delete filePath;
				
			}

		} else {
		
			cout << "No files changed" << endl;
			
		}
		
		cout << endl;
		cout << "just showing changes as requested by the '-f' switch" << endl;
		cout << "exiting now" << endl;
		cout << endl;
		
		return 0;
		
	}
	
	//compress
	
	if (verbose==true) cout << "--------compress---------" << endl;
	
	list <string *> encryptFiles;
	
	while(compressFiles.size()>0) { 
		
		string * filePath=compressFiles.front();
		compressFiles.pop_front();
		
		if (verbose==true) cout << "**compressing: " << *filePath << endl;
		
		string * newFilePath = new string;
		
		newFilePath->append(*filePath);

		int c=0;
		
		//convert file path slash marks to ___
		while ( c<newFilePath->size() ) {
			
			//if a slash has been escaped, replace it with one slash
			c=newFilePath->find("/", c);
			
			if (c!=string::npos) {
			
				newFilePath->replace(c, 1, "___");
				c++;
				
			} else {
				break;
			}
			
		}

		c=0;
		
		//convert file path dots marks to _-_
		while ( c<newFilePath->size() ) {
			
			//if a slash has been escaped, replace it with one slash
			c=newFilePath->find(".", c);
			
			if (c!=string::npos) {
			
				newFilePath->replace(c, 1, "_-_");
				c++;
				
			} else {
				break;
			}
			
		}
		
		*newFilePath=".ss3_temp_work/"+hostname+*newFilePath+".bz2";
		//cout << "file to be compressed: " << *newFilePath << endl;
		
		ifstream inFile(filePath->c_str(), ios::binary|ios::ate);
		if (inFile.is_open()) {
			
			size=inFile.tellg();
			
			//cout << "current size: " << size << endl;
						
			inFile.seekg(0, ios::beg);
			
			int bzError;
			const int BLOCK_MULTIPLIER = 7;

			FILE * outFile = fopen(newFilePath->c_str(), "wb");
			
			if(outFile!=NULL){
				
				char * compressBuffer = new char[4096];
			
				BZFILE *pBz = BZ2_bzWriteOpen(&bzError, outFile, BLOCK_MULTIPLIER, 0, 30);			
				int bytesRead=0;
				
				c=0;
				while( c < size ) { 
					
					bytesRead=inFile.readsome( (char *) compressBuffer, 4096);
					BZ2_bzWrite(&bzError, pBz, compressBuffer, bytesRead);
					
					if (bzError!=BZ_OK) {
						
						if (bzError==BZ_PARAM_ERROR) {
							cerr << "compressor parameter error - error code: " << bzError << endl;
						}
						if (bzError==BZ_SEQUENCE_ERROR) {
							cerr << "compressor sequence error - error code: " << bzError << endl;
						}
						if (bzError==BZ_IO_ERROR) {
							cerr << "compressor I/O error - error code: " << bzError << endl;
						}

						//clean up some stuff
						BZ2_bzWriteClose(&bzError, pBz, 0, NULL, NULL);
						
						fclose(outFile);
						inFile.close();
						
						return 4;
						
					}
					
					c+=bytesRead;
					
				}
				
				BZ2_bzWriteClose(&bzError, pBz, 0, NULL, NULL);
				
				fclose(outFile);
				
				delete compressBuffer;
				
				encryptFiles.push_back( newFilePath );
				
			} else {
				
				//clean up some stuff
				inFile.close();
				
				while(compressFiles.size()>0) { 
			
					string * tFilePath=compressFiles.front();
					compressFiles.pop_front();
					delete tFilePath;
					
				}

				cerr << "couldn't open output compress file - " << *newFilePath << endl;
				return 3;
				
			}
			
			inFile.close();
			
		} else {
			
			while(compressFiles.size()>0) { 
		
				string * tFilePath=compressFiles.front();
				compressFiles.pop_front();
				delete tFilePath;
				
			}
			
			delete filePath;
			cerr << "couldn't open input compress file" << endl;
			return 3;
		}
		
		delete filePath;
		
	}

	if (verbose==true) cout << "--------encrypt---------" << endl;
	
	list <string *> transmitFiles;
	
	const int TAG_SIZE = 12;
	
	string keyHash;
	byte keyHashBytes[ AES::DEFAULT_KEYLENGTH ];
	
	CryptoPP::SHA hash;
	StringSource keyHashCreator( password, true, new HashFilter( hash, new StringSink( keyHash ), true ) );
	
	for(int t=0;t<keyHash.length();t++) {
		keyHashBytes[t]=(byte)keyHash[t];
	}
	
	while(encryptFiles.size()>0) {
	
		string * filePath=encryptFiles.front();
		encryptFiles.pop_front();
		
		if (verbose==true) cout << "**encrypting: " << *filePath << endl;
		
		string * newFilePath = new string;
		newFilePath->append(*filePath);
		newFilePath->append(".aes");
		
		try	{
			
			GCM< AES >::Encryption aesGCM;
			aesGCM.SetKeyWithIV( keyHashBytes, sizeof(keyHashBytes), systemIv, sizeof(systemIv) );
			
			FileSource source(filePath->c_str(), true, new AuthenticatedEncryptionFilter( aesGCM, new FileSink( newFilePath->c_str() ), false, TAG_SIZE) );
			
			transmitFiles.push_back( newFilePath );
			
		}	catch( CryptoPP::InvalidArgument& e ) {
			cerr << "Caught InvalidArgument..." << endl;
			cerr << e.what() << endl;
			cerr << endl;
		} catch( CryptoPP::Exception& e ) {
			cerr << "Caught Exception..." << endl;
			cerr << e.what() << endl;
			cerr << endl;
		}
				
	}
	
	if (verbose==true) cout << "--------transmit---------" << endl;
	
	string s3Path;
	
	S3BucketContext bucketContext = {
		host.c_str(),
		bucket.c_str(),
		S3ProtocolHTTP,
		S3UriStylePath,
		accessKeyId.c_str(),
		secretAccessKey.c_str()
	};
	
	S3ResponseHandler responseHandler = {
		&responsePropertiesCallback,
		&responseCompleteCallback
	};
	
	S3_initialize("ss3", S3_INIT_ALL, host.c_str());
	
	S3PutObjectHandler putObjectHandler =
	{
		responseHandler,
		&putObjectDataCallback
	};

		
	ifstream * file = new ifstream();
	while(transmitFiles.size()>0) { 
		
		string * filePath=transmitFiles.front();
		transmitFiles.pop_front();
		
		if (verbose==true) cout << "**transmitting: " << *filePath << endl;
		
		put_object_callback_data data;
		
		file->open(filePath->c_str(), ios::binary|ios::ate);
		if (file->is_open()) {
			
			data.contentLength = file->tellg();
			file->seekg (0, ios::beg);
			data.ifile=file;
			
			string newFilePath;
			newFilePath.append(*filePath);
			int c=0;
			
			c=newFilePath.find(".ss3_temp_work/", c);
			
			if (c!=string::npos) {
			
				newFilePath.replace(c, 15, "");
				
			}
			
			s3Path="ss3backup/"+newFilePath;
			
			if (verbose==true) cout << "**transmitting to: " << s3Path << endl;
			
			S3_put_object(&bucketContext, s3Path.c_str(), data.contentLength, NULL, NULL, &putObjectHandler, &data);
			
		} else {
		
			cerr << "couldn't open file for transmission to S3" << endl;
			
			while(transmitFiles.size()>0) { 
		
				string * tFilePath=transmitFiles.front();
				transmitFiles.pop_front();
				delete tFilePath;
				
			}
			
			delete file;
			
			return 4;
			
		}
		
		file->close();
		
		delete filePath;
		
	}
	
	delete file;
	
	S3_deinitialize();
	
	if (verbose==true) cout << "done...  peace out..." << endl;

	delete db;
	
	return 0;

}

static int putObjectDataCallback(int bufferSize, char *buffer, void *callbackData)
{
	put_object_callback_data *data = (put_object_callback_data *) callbackData;

	int ret = 0;

	if (data->contentLength) {
		int toRead = ( (data->contentLength > (unsigned) bufferSize) ? (unsigned) bufferSize : data->contentLength);
		//ret = fread(buffer, 1, toRead, data->infile);
		ret = data->ifile->readsome( (char *)buffer, toRead );
	}
	data->contentLength -= ret;
	return ret;
}
