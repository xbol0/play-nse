# play-nse

My nse scripts and cheat sheet

## Quick links

- [NSE Reference](https://nmap.org/nsedoc/index.html)
- [API](https://nmap.org/book/nse-api.html)
- [Document](https://nmap.org/book/nse.html)
- [Lib nmap](https://nmap.org/nsedoc/lib/nmap.html)
- [Lib stdnse](https://nmap.org/nsedoc/lib/stdnse.html)
- [Lib http](https://nmap.org/nsedoc/lib/http.html)
- [Lib url](https://nmap.org/nsedoc/lib/url.html)
- [Lib pcre](https://nmap.org/nsedoc/lib/pcre.html)

## Scripts

### http-graphql

This is a script to detect graphql api entry. 
Now WIP, because when I test my Deno server, it caused a panic.

Usage:

```
# Basic
nmap --script http-graphql -p80,443,9000 example.com

# With authorization
nmap --script http-graphql -p80,443,9000 --script-args 'auth-token="xxx"' example.com
nmap --script http-graphql -p80,443,9000 --script-args 'auth-cookie="xxx"' example.com
```