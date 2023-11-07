EASY Github Tutorial: https://product.hubspot.com/blog/git-and-github-tutorial-for-beginners

Instructions notes: 

```Another option is to start from the v0.5 implementation and to extend it with the security features specified in v1.0. These include extending the login protocol with session key establishment (key exchange and key derivation) and extending the message transfer protocol with cryptographic functions and replay protection. In both cases, you should first read carefully and understand the specification of SiFT v1.0. Then, you should either implement the entire protocol or add the requiered new features to the existing v0.5 implementation. IMPORTANT: in the latter case, you only need to modify login.py, mtp.py, server.py and client.py!```

```You will need to generate an RSA key-pair for the server. For this, you can write a standalone utility program based on what you did in the corresponding exercise session. You should export and save the public key and the key-pair in different files (e.g., in PEM format), and put the key-pair file in the server folder and the public key file in the client folder. So your server and client programs can read these keys from those files and pass them to the login protocol that will use them for the session key establishment. Essentially, this is the only new thing you have to implement in server.py and client.py, and the bulk of the work will be in mtp.py and login.py.```

I think the RSA will be easy bc the exercise solution is on the Moodle. That will just be a simple implementation and then login and mtp are the big ones so idk how to divide roles.


Questions to ask 11/7
1. double check we're passing the transfer key properly from login to mtp (setter function?)
