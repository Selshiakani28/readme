# Authentication by encrypted negative password </br>
## Aim:</br>
  - Instead of transmitting the password for authentication,its encrypted hash value is verified.</br>
## Steps: </br>
  - Recieve plain password from client.</br>
  - Plain password hashed through a cryptographic hash function.</br>
  - Hashed password is converted to negative password</br>
  - The negative password is encrypted using a symmetric encryption technique and transmitted.</br>
## Advantages of encrypted negative password:</br>
  - Only the encrpted form of negative hash is stored in the authentication table.</br>
  - Resists lookup table attack,rainbow attack etc.</br>
  - Hash is irreversible therefore only verification is possible with hash.</br>
## Algorithm for negative password generation:</br>
  i/p<-binary_pass</br>
  o/p<-string</br>
  for i in 1 to 256:</br>
    for j in 1 to i-1:</br>
       string[j]<-binary_pass[j]</br>
    string[i]=1-binary_pass[i]</br>
    for j in i+1 to 256:</br>
        string[i]='*'</br>
## Encryption</br>
  - Plain password is passed to a hash function like SHA-256 and hashed password of 256 bits is generated.</br>
  - The hexadecimal hash value is converted to binary form(binary_pass).</br>
  - The output is then passed to a p-box.</br>
  - Converted to a hexadecimal value and passed to AES algorithm.</br>
  - An encrypted hexadecimal value is produced.(Encrypted negative password)</br>
## Decryption</br>
  - The recieved encrypted negative password is decrypted and stored in the authentication table.</br>
  - Whenever the user logs in the encrypted negative password is sent and it is decrypted at the server and checked with the hash value stored in the authentication table.</br>
  - By doing so the lookup table attack and rainbow attck is prevented.</br>
  
  
    
     
       
