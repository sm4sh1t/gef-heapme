"""
Heap Made Easy - Heap Analysis and Collaboration Tool
https://heapme.f2tc.com/

HeapME is a tool that helps simplify heap analysis and collaboration through an intuitive web interface. 

Features:
- GEF patches to allow scripts to register functions to malloc, calloc, realloc and free events.
- An HTTP Log Server will receive logs sent form the exploit code and upload them in the correct order.

@htejeda
"""
import time
import json
import requests
import socketio
import threading
import asyncio
import os
from aiohttp import web

heapme_is_authorized = False
heapme_is_running = False

sio = socketio.Client()

"""
Allow overriding default log listening host and port with environment variables
"""
LOG_SRV_HOST = os.getenv('LOG_SRV_HOST') or '127.0.0.1'
LOG_SRV_PORT = int(os.getenv('LOG_SRV_PORT') or 4327)

@register_command
class HeapMe(GenericCommand):
    """Heap Made Easy

init -- Connect to the HeapMe URL and begins tracking dynamic heap allocation
watch -- Updates the heap layout when this breakpoint is hit
push -- Uploads all events to the HeapME URL
"""

    _cmdline_ = "heapme"
    _syntax_  = "{:s} (init|watch|push)".format(_cmdline_)

    def __init__(self):
        super(HeapMe, self).__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.usage()
        return

@register_command
class HeapMeInit(GenericCommand):
    """Connect to the HeapMe URL and begins tracking dynamic heap allocation"""

    _cmdline_ = "heapme init"
    _syntax_  = "{:s} <url> <id> <key>".format(_cmdline_)
    _example_ = "{0:s} https://heapme.f2tc.com 5e7f8edea867881836775db1 e50b08b0-711c-11ea-9d36-a18c10d09858".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):

        if not argv or len(argv) != 3:
            self.usage()
            return

        print(r"""
             _   _                  __  __ _____
            | | | | ___  __ _ _ __ |  \/  | ____|
            | |_| |/ _ \/ _` | '_ \| |\/| |  _|
            |  _  |  __/ (_| | |_) | |  | | |___
            |_| |_|\___|\__,_| .__/|_|  |_|_____|
                             |_|
        """.center(40))

        _heapme_url = argv[0]
        _heapme_id = argv[1]
        _heapme_key = argv[2]

        if _heapme_url.endswith('/'):
            _heapme_url = _heapme_url[:-1]
        
        _heapme_url = "{0:s}/{1:s}/{2:s}".format(_heapme_url, _heapme_id, _heapme_key)
        req = requests.get(_heapme_url)
        data = req.json()

        if 'result' in data:
            warn("{0}: {1} - {2}".format(
                Color.colorify("HeapME", "blue"),
                Color.colorify(_heapme_url, "underline blue"),
                Color.colorify(data['result'], "red")
            ))

            return False

        if not data['is_empty']:
            if not self.confirm("oOps!, the specified URL contains data of previous analysis, do you want to overwrite it? [y/n] "):
                print("Bye!")
                return

        sio.connect(_heapme_url)
        sio.emit('address', { 'id': _heapme_id, 'key': _heapme_key })

        while not heapme_is_authorized:
            time.sleep(1)

        ok("{0}: connected to {1}".format(
            Color.colorify("HeapME", "blue"),
            Color.colorify(argv[0], "underline blue"),
        ))

        set_gef_setting("heapme.enabled", True, bool, "HeapME is Enabled")
        set_gef_setting("heapme.verbose", False, bool, "HeapME verbose mode")

        _sec = checksec(get_filepath())

        heapme_push({
            'type': 'begin',
            'filepath': get_filepath(),
            'checksec': {
                'Canary': _sec["Canary"],
                'NX': _sec["NX"],
                'PIE': _sec["PIE"],
                'Fortify': _sec["Fortify"],
                'RelRO': "Full" if _sec["Full RelRO"] else "Partial" if _sec["Partial RelRO"] else "No"
            }
        })

        gef_on_exit_hook(self.clean)

    @gef_heap_event("__libc_malloc", "__libc_calloc", "__libc_realloc", "__libc_free")
    def heap_event(**kwargs):

        if not get_gef_setting("heapme.enabled"):
            return

        heapme_push({
            "type": kwargs["name"],
            "data": {
                "address": kwargs["address"],
                "size": -1 if kwargs["name"] == "__libc_free" else kwargs["size"]
            }
        })

        heapme_update()

    def confirm(self, msg):

        valid = { "y": True, "yes": True, "n": False, "no": False }

        while True:
            choice = input(msg)

            if choice in valid:
                return valid[choice]
            else:
                print("Please respond with 'y' or 'n' (or 'yes' or 'no')")

    def clean(self, event):
        global heapme_is_running

        print("Hold on, {0} is exiting cleanly".format(Color.colorify("HeapME", "blue")), end="...")

        heapme_push({'type': 'done'})
        sio.disconnect()
        heapme_is_running = False

        print("Adios!")
        gef_on_exit_unhook(self.clean)

@register_command
class HeapMeWatch(GenericCommand):
    """Updates the heap layout when this breakpoint is hit"""

    _cmdline_ = "heapme watch"
    _syntax_  = "{:s} <address>".format(_cmdline_)
    _example_ = "{0:s} *0x0xbadc0ffee0ddf00d".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):

        if not argv or len(argv) != 1:
            self.usage()
            return

        if not get_gef_setting("heapme.enabled"):
            return

        HeapMeWatchAddress(argv[0])
        ok("HeapMe will update the heap chunks when the {0:s} breakpoint is hit".format(Color.colorify(argv[0], "yellow")))

@register_command
class HeapMePush(GenericCommand):
    """Uploads all events to the HeapME URL"""

    _cmdline_ = "heapme push"
    _syntax_  = "{:s}".format(_cmdline_)
    _example_ = "{0:s}".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):

        if not get_gef_setting("heapme.enabled"):
            return

        heapme_push()

@sio.event
def message(data):
    global heapme_is_authorized

    if type(data) is dict and data['authorized']:
        heapme_is_authorized = True
        return
    else:
        err("{0:s}: {1:s}".format(Color.colorify("HeapME", "blue"), data))
        sio.disconnect()

    print(data)


class HeapMeWatchAddress(gdb.Breakpoint):
    def stop(self):
        heapme_update()

        return False

def _get_heap_segment():

    heap_section = [x for x in get_process_maps() if x.path == "[heap]"]
    if not heap_section:
        #err("No heap section")
        return

    arena = get_main_arena()
    if arena is None:
        #err("No valid arena")
        return

    heap_section = heap_section[0].page_start

    top_chunk_addr = int(arena.top)
    view_size = (top_chunk_addr - heap_section + 16) / 8
    cmd = "x/%dxg %s" % (view_size, heap_section)

    heap_region = gdb.execute(cmd, to_string=True)
    return heap_region

def heapme_update():

    if not get_gef_setting("heapme.enabled"):
        return

    #Used to restore previous gef.disable_color setting
    _prev_gef_disable_color = get_gef_setting("gef.disable_color")

    #Temporarily disable color to simplify parsing
    set_gef_setting("gef.disable_color", True)

    arenas = {'type': 'arenas', 'data': False}
    try:
        arena = GlibcArena(__gef_default_main_arena__)
        arenas = {'type': 'arenas', 'data': str(arena)}

    except gdb.error:
        arenas = {'type': 'arenas', 'data': False}
        return

    fast     = gdb.execute("heap bins fast", to_string=True)
    tcache   = gdb.execute("heap bins tcache", to_string=True)
    unsorted = gdb.execute("heap bins unsorted", to_string=True)
    small    = gdb.execute("heap bins small", to_string=True)
    large    = gdb.execute("heap bins large", to_string=True)
    chunks   = gdb.execute("heap chunks", to_string=True)

    _new_event = [
        arenas,
        { 'type':'fast', 'data': str(fast) },
        { 'type':'tcache', 'data': str(tcache) },
        { 'type':'unsorted', 'data': str(unsorted) },
        { 'type':'small', 'data': str(small) },
        { 'type':'large', 'data': str(large) },
        { 'type':'chunks', 'chunks_summary': str(chunks), 'data':_get_heap_segment() }
    ]

    #Restore previous setting
    set_gef_setting("gef.disable_color", _prev_gef_disable_color)

    heapme_push(_new_event)

def heapme_push(heapme_events = False):

    if type(heapme_events) is dict:
        heapme_events = [ heapme_events ]

    if not get_gef_setting("heapme.enabled") or not heapme_events:
        return

    if get_gef_setting("heapme.verbose"):
        print("{0:s}: Uploading event".format(Color.colorify("HeapME", "blue")))

    sio.emit('push', heapme_events)

def hm_log_server():
    async def logHandler(request):
        data = await request.json()
        
        if not get_gef_setting("heapme.enabled"):
            return

        heapme_push({ 'type': 'log', 'data': data['msg'] })

        return web.Response(text="OK")

    app = web.Application()
    app.add_routes([web.post('/', logHandler)])
    runner = web.AppRunner(app)
    return runner

def hm_run_log_server(runner):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, host=LOG_SRV_HOST, port=LOG_SRV_PORT)
    loop.run_until_complete(site.start())
    loop.run_forever()

t = threading.Thread(target=hm_run_log_server, args=(hm_log_server(),))
t.daemon = True
t.start()

register_external_command(HeapMe())
