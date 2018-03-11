# HIBP (Have I Been Pwned)

A command-line password checker built on top of the
https://github.com/mattevans/pwned-passwords library.

Install with `go get -u github.com/apiarian/hibp`.

See `hibp -help` for usage information.

# Have my [`pass`](https://www.passwordstore.org/) passwords been pwned?

A bash one-liner:

```bash
find $HOME/.password-store -name '*.gpg' | \
sed "sx${HOME}/\.password-store/xx" | \
sed s/.gpg// | \
xargs -n1 -I key sh -c \
'echo "key \c";
pass show key | head -n1 | hibp --stdin > /dev/null;
export OUT=$?;
if [ "$OUT" -eq "0" ];
    then echo ok;
elif [ "$OUT" -eq "2" ];
    then echo NOT OK;
else
    echo error;
fi'
```
