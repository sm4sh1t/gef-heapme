
![gef-context](https://heapme.f2tc.com/img/heapme-gdb-console.png)

## About this fork ##

`GEF` script and heap-analysis-helper patches to integrate with `HeapME` _(Heap Made Easy)_: https://heapme.f2tc.com/

* malloc/calloc/realloc/free updates the HeapME events array.
* An HTTP Log Server will receive logs sent form the exploit code and upload them in the correct order.

## How to use ##
1. Register and Login to https://heapme.f2tc.com/
2. Create a HeapME URL + Key
3. Load the heapme.py GEF script: \
`gef➤  source gef/scripts/heapme.py` \
_or append the line "sources ~/gef/scripts/heapme.py" to your .gdbinit._
4. Execute `heapme init https://heapme.f2tc.com/ <id> <key>` after `heap-analysis-helper`
5. Access and share the read-only page: `https://heapme.f2tc.com/<id>`

### HeapME Commands ###
* __heapme init &lt;id&gt; &lt;key&gt;__: Connect to the HeapMe URL and begins tracking dynamic heap allocation.
* __heapme watch &lt;address&gt;__: Updates the heap layout when this breakpoint is hit.
* __heapme push__: Uploads all events to the HeapME URL on-demand.

## Logging ##

Import following script to push logging messages to the HeapME console:

_heapme_logging.py_ :
```python
import json
import requests
from pwn import *

class HeapmeLogging:

    def __init__(self):
        self.DEBUG = True
        self.is_open = False
        self.url = 'http://127.0.0.1:4327/'

    def info(self, message):
        if self.DEBUG:
            print(message)

        try:
            res = requests.post(self.url, json={ 'msg': message }, headers={'Content-type': 'application/json'})
            
        except requests.ConnectionError, e:
            print(str(e))
```

### Usage Example: ###

```python
from pwn import *
import heapme_logging
#...

gdb.attach(p, '''heap-analysis-helper
heapme init https://heapme.f2tc.com/ 5e84d30c33c2261b3254a303 7ec2a091-33c4-51ea-25d1-5de031cc6374''')
pause()

#...

log = HeapmeLogging()

log.info('HeapME')
```

### Using Docker: ###

A docker container is provided with HeapMe and pwntools pre-installed.

```bash
# building your docker image
docker build . -t heapme

# running your exploit in the docker lab with *tmux* for split window side-by-side debugging
# exposing logging port and host
cd ~/my-heapme-lab
docker run -it --cap-add=SYS_PTRACE -eLOG_SRV_HOST=0.0.0.0 --rm --name heapme_lab -v `pwd`:/root heapme tmux new -- python3 xploit.py
```

```python
# using tmux for side-by-side debugging in your pwntools exploit

# ...

context.terminal = ['tmux', 'split-window', '-h']
gdb.attach(p, '''heap-analysis-helper
heapme init https://heapme.f2tc.com/ 5e84d30c33c2261b3254a303 7ec2a091-33c4-51ea-25d1-5de031cc6374''')
pause()

# ...

```

### TODO ###

* Interactive two-way communication between `HeapME` and `GEF`
* Create a GEF setting that will allow heap-analysis-helper commands to return an object besides using gef_print
