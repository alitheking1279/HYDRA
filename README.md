# HYDRA
Hydra is a C++ based information security tool suite which can perform both offensive and defensive functionalities. From encryption/decryption of all file fromats and steganography to hash cracking and simplified port scanning it can do it all.
This project was made with the help of 3 members one handled the Portscanning/simple cracker and one handled the UI I did the rest.
This project is like a swiss army knife of infosec tools although the functionality is limited because we went for breadth instead of depth.
The Encryption is handled using AES-256-GCM algorithm and the key is made by parsing a user thring through a password based key derivation function
The stegonagraphy is LSB steganography to wipe out the lsb of the Image's certain color channel and embed our payload in it
The payload itself is compressed which (although it was not planned but cerainly adds a nice touch) adds to the randomness of bit distribution in the LSB allowing it to bypass the Chi-Squared test for stegAnalysis
the encrypted Database................ The class went through many many modifications first version used a .txt and it was encrypted via a master key but it was suseptible to corruption and data loss so we switched to a more bulletproof database and SQLite was a perfect choice the encrypted idea was to use a master key hidden in an image and use that but due to time constraints it is still pending 
The Offensive Side is a playground of tools some are intentionally capped to prevent malicious or illegal abuse like port scanner or hash cracker
The John class was heavily inspired by the existing JTR tool online and although ours is a fraction of the capabalities and power.
I wanted to add GPU accelerated hash cracking and more powerful multithredaing but my System is as old as my grandparents plus my skilllset and understanding are not that evolved to apply and implement these techniques whilst also keeping the Code optimized
I'll come back to improve this project once i get a decent rig till then i hope it performs to your satisfaction
