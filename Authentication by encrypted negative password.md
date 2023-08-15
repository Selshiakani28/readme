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
  <pre>
  for i in 1 to 256:</br>
    for j in 1 to i-1:</br>
       string[j]<-binary_pass[j]</br>
    string[i]=1-binary_pass[i]</br>
    for j in i+1 to 256:</br>
        string[i]='*'</br>
 </pre>
        
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
  
  ## Code</br>
  import hashlib
import math
def hexaToBin(n):
 
 if(n=='0'):
       return("0000")
 if(n=='1'):
       return("0001")
 if(n=='2'):
       return("0010")
 if(n=='3'):
       return("0011")
 if(n=='4'):
       return("0100")
 if(n=='5'):
       return("0101")
 if(n=='6'):
       return("0110")
 if(n=='7'):
       return("0111")
 else:
   ini_string = n
  
# Printing initial string
   #print ("Initial string", ini_string)
  
# Code to convert hex to binary
   n = int(ini_string, 16) 
   bStr = ''
   while n > 0:
    bStr = str(n % 2) + bStr
    n = n >> 1    
   res = bStr
   return str(res) 
# Print the resultant string
   #print ("Resultant string", str(res))
def binToHexa(n):
    
    # convert binary to int
    num = int(n, 2)
      
    # convert int to hexadecimal
    hex_num = hex(num)
    return(hex_num)
# initializing string
print("enter password to encrypt")
str1=input()
rows=8
cols=int(rows/4)
# encoding GeeksforGeeks using encode()
# then sending to SHA256()
result = hashlib.sha256(str1.encode())

  
# printing the equivalent hexadecimal value.
print("The hexadecimal equivalent of SHA256 is : ")
my_hexdata=result.hexdigest()

#print(my_hexdata)
scale = 16 ## equals to hexadecimal

num_of_bits = rows

print(len(bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)))

bin_dig=bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
#print(bin_dig)
print("The original hash value is " + str(bin_dig))
#print(len(bin_dig)) 
# using map()
# to convert number to list of integers
bin_digest = list(map(int, str(bin_dig)))
 
# printing result
#print("The list from number is " + str(bin_digest))
#a=[0,1,0,1]
x=[]
p=-1
#rows, cols=256,256
for r in range(0,rows):
    col = []
    for s in range(0,rows):
        col.append(0)
    x.append(col)
#print(x)
x1=[]
for  r in range(rows):
    col = []
    for s in range(rows):
        col.append(0)
    x1.append(col)
#print(x1)
for i in range(0,rows):
    #print("i=",i)
    for p in range(0,i):
        x[i][p]=bin_digest[p]
        #print("x=",x[i][p])
        #print("j=",p)
    l=p+1
    #print("L=",l)
    for k in range(l,rows):
       x[i][k]="*"
       #print("y=",i,x[i][p])
    #print("p=",l)
    x[i][i]=1-bin_digest[l]
'''for i in range(0,256):
    #for j in range(0,256):
    print(x[i],"\t")
    print("\n")
    '''
#print("\n")
#print("x",x)
#permut=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]
#print("x",x)
#permut=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161]
permut=[0,1,2,3,4,5,6,7]
#permut=[0,1,3,6,4,5,2,7,9,8,11,10]
for i in range(0,rows):
    for j in range(0,rows):
        x1[i][j]=x[i][permut[j]]
#print("\n negative password before before pi' \n")
p1=[]
for  r in range(rows):
    col = []
    for s in range(rows):
        col.append(0)
    p1.append(col)
#print(p1)
#print("\n")
for i in range(0,rows):
    for j in range(0,rows):
      if x1[i][j]=="*":
       if j%4==0:
         if j%8==0:
             if j%16==0:
              p1[i][j]=0
         #print(y1[i][j])
              #print("\n")
             else:
               p1[i][j]=1
         else:
           p1[i][j]=0
      else:
         p1[i][j]=x1[i][j]
#print(p1)
hexa_out=[]
for  r in range(rows):
    col = []
    for s in range(cols):
        col.append(0)
    hexa_out.append(col)
#print(hexa_out)
    
for i in range(0,rows):
    j=0
    t=0
    while(j<rows-3):
       s=""
       for k in range(0,4):
           s=s+str(p1[i][j+k])
       j=j+4
       
       hexa=binToHexa(s)
       hexa_out[i][t]=hexa
       t=t+1
       #print(hexa_out[i])
#print(hexa_out)
#print(hexa_out[0][0][0])
hexa_out_new=[]
for  r in range(rows):
    col = []
    for s in range(cols):
        col.append(0)
    hexa_out_new.append(col)
#print(hexa_out_new)
for i in range(0,rows):
    s=""
    for j in range(0,cols):
        s=s+hexa_out[i][j][2]
    #print(s)   
    hexa_out_new[i]=s
#print("hexa_out_new",hexa_out_new)
'''
hex_str=""
for i in range(0,10):
  for j in range(0,2):
     hex_str=hex_str+(hexa_out[i][j])
     print(hex_str[i])
     '''
'''
scale = 16 ## equals to hexadecimal

num_of_bits = 4

bina=bin(int(hexa, scale))[2:].zfill(num_of_bits)
print(bina)
'''

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
key = get_random_bytes(16)
decrypt_str=[]
for i in range(0,rows):
  #for j in range(0,2):
  str1=(hexa_out_new[i])
  str_1 = bytes(str1,'UTF-8')
  print("str1",str1)
  data=str_1
  #key = get_random_bytes(16)
  print("key",key)
  cipher = AES.new(key, AES.MODE_EAX)
  ciphertext, tag = cipher.encrypt_and_digest(data)
  #print("cipher text",ciphertext)
  #print("cipher",cipher)
  #print("tag",tag)
  #print(str_1)
  nonce = cipher.nonce
  #print("nonce",nonce)
  
  cipher = AES.new(key, AES.MODE_EAX, nonce)
  data = cipher.decrypt_and_verify(ciphertext, tag)
  #print(data)
  #print(data.decode())
  #print(str1)
  #print(hexa_out_new[i])
  decrypt_str.append(data.decode())
print("decrypt_str",decrypt_str)
s=[]
for i in range(0,len(decrypt_str)):
  '''ini_string = decrypt_str[i]
  scale = 16
  
# Printing initial string
  print ("Initial string", ini_string)
  
# Code to convert hex to binary
  res = bin(int(ini_string, scale))
  
# Print the resultant string
  print ("Resultant string", str(res))

'''
  for j in range(0,int(rows/4)):
    s.append(hexaToBin(decrypt_str[i][j]))
#print("s=",s)
#print(s[0][1],s[1][1])
str_list=[]
k=0
p1=[]
for  r in range(len(decrypt_str)):
    col = []
    for r1 in range(rows):
        col.append(0)
    str_list.append(col)
t=0
for i in range(0,len(decrypt_str)):
 m=0
 k=0
 while(m<int(rows/4)):
    
    p=0
    for j in range(0,4):
       
       str_list[i][k]=(s[t][p])
       k=k+1
       p=p+1
    t=t+1
    m=m+1

#print("str_list",str_list)
permut_list=[]
for  r in range(len(decrypt_str)):
    col = []
    for r1 in range(rows):
        col.append(0)
    permut_list.append(col)
new_order=[]

    
     
       
