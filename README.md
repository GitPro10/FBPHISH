<h1 align="center">FBPHISH</h1>


### [√] Description :

***A python phishing script for facebook login phishing***

### [+] Installation

##### Install primary dependencies (git, python)

 - For Debian (Ubuntu, Kali-Linux, Parrot)
    - ```sudo apt install git python3 php openssh-client -y```
 - For Termux
    - ```pkg install git python3 php openssh -y```

##### Clone this repository

 - ```git clone https://github.com/GitPro10/FBPHISH```

##### Enter the directory
 - ```cd FBHISH```

##### Install all modules
 - ```pip3 install -r files/requirements.txt```

##### Run the tool
 - ```python3 fb_phish.py```

#### Or, directly run
```
wget https://raw.githubusercontent.com/GitPro10/FBPHISH/main/fb_phish.py && python3 fb_phish.py

```


### Support

OS         | Support Level
-----------|--------------
Linux      | Excellent
Android    | Excellent

### Features:

 - Cloudflared tunneling
 - Credentials mailing
 - Easy to use
 - Possible error diagnoser
 - Built-in masking of URL
 - Custom masking of URL
 - URL Shadowing
 - Portable file (Can be run from any directory)
 - Get IP Address and many other details along with login credentials


### Requirements

 - `Python(3)`
   - `requests`
   - `bs4`
   - `rich`
 - `PHP`
 - `SSH`
 
If not found, php, ssh and python modoules will be installed on first run

#### Tested on

 - `Termux`
 - `Ubuntu`

## Usage

1. Run the script
2. Choose a Website
3. Wait sometimes for setting up all
4. Send the generated link to victim
5. Wait for victim login. As soon as he/she logs in, credentials will be captured


## Solution of common issues
 - Some secured browsers like Firefox can warn for '@' prefixed links. You should use pure links or custom link to avoid it.
 - Termux from play store in not supported. Download termux from fdroid or github
 - VPN or proxy prevents tunneling and even proper internet access. Turn them off if you have issues.
 - Some android requires hotspot to start Cloudflared. If you face 'tunneling failed' in android, most probably your hotspot is turned off.
 - If you want mailing credentials then you need to use app password. Visit [here](https://myaccount.google.com/u/0/apppasswords) and generate an app password, put that in `files/email.json`. You may need to enable 2FA before it.

## [!] Disclaimer
***This tool is developed for educational purposes. Here it demonstrates how phishing works. If anybody wants to gain unauthorized access to someones social media, he/she may try out this at his/her own risk. You have your own responsibilities and you are liable to any damage or violation of laws by this tool. The author is not responsible for any misuse of FBPHISH!***


## Credits:

[*KasRoudra*](https://github.com/KasRoudra)
> All credits goes to him. He is the original author of this tool and I just modified it for Facebook phishing only.

**Original project:** [*MaxPhisher*](https://github.com/KasRoudra/MaxPhisher)