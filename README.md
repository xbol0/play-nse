# play-nse

My nse scripts and cheat sheet

[NSE Reference](https://nmap.org/nsedoc/index.html)

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