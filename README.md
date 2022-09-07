## C++ Backup

This is a tool I briefly used to mass compress, encrypt, and upload backup files to AWS S3.  I've moved on to **RClone** if I need a tool to do the same thing.

I'm purposly not including the recovery tool because I don't want people to actually use this tool.  It's here more to show some C++ code that I've written.

I wrote this back in 2014.

## Tech Used

Uses **LevelDB** for settings and other associated functions.
https://github.com/google/leveldb

Uses **BZIP2** for compression.
https://sourceware.org/bzip2/

Uses **Crypto++** to do the actual encryption, using **AES-GCM** for the specific encryption algorithm.
https://cryptopp.com/

Uses LibS3 to help with handling S3.
https://github.com/bji/libs3

Finally, it uses **TCLAP** for command line parsing.
https://github.com/mirror/tclap

## How It Works

This is a CLI tool.  It takes some forced and some optional command line arguments to set up the software.

If on run it doesn't find a ~/.ss3db/ directory (leveldb settings), then it starts generating encryption settings.

It then starts scanning for directories and files from the directory that you run the tool in.  The directory scanner is a couple of queues that decend into directories as they are found, that are then added to the back of the queue.  Files are also added to a queue as they are found.

It then goes through a loop to check the sha hash of each file from the previous version (if there is any).  If anything has changed, it adds that file to another queue for compression.  In this loop, it also adds the sha hash of the file in question to the LevelDB database.

It then passes this to a loop that encrypts each file, then transmits it to AWS S3.

## Dev Setup

Since I'm only showing this as an example of code I've written, I'll leave it up to the person reviewing this system to build and install the above software libraries to run the system.  If I feel obliged, I'll update this another time to show the installation process.

