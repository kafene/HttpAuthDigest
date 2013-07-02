# kafene\HttpAuth

A PHP class for user logins via HTTP Digest Authentication.

It includes a simple brute force protection by not allowing
the same IP address to attempt to log in more than X number
of times in the same interval. Both the interval and number
of allowed attempts are user specified.

Even though digest auth has the `nc` value that tracks the
number of login attempts, this could be spoofed by a malicious
user and so instead this tracks attempts independently.

Example usage:

```php
$auth = new kafene\HttpAuthDigest;
$auth->addUser('user', 'pass');
if($auth->authenticate()) {
    print 'Welcome!';
}
```

This is free and unencumbered software released into the public domain.
For more information, please refer to <http://unlicense.org/>
