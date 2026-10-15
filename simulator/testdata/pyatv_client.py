"""Independent, opt-in pyatv client used by TestMRPPyatvInterop.

Install pyatv in a virtualenv and set PYATV_PYTHON to its Python executable.
Only simulator credentials and loopback connections are used.
"""
import asyncio
from ipaddress import ip_address
import json
from pathlib import Path
import sys
import pyatv
from pyatv.conf import AppleTV, ManualService
from pyatv.const import Protocol

async def main():
    config = AppleTV(ip_address("127.0.0.1"), "Go MRP simulator")
    config.add_service(ManualService("simulator", Protocol.AirPlay, int(sys.argv[1]),
        {"model": "AppleTV14,1", "osvers": "17.0", "features": "0x0,0x40"},
        credentials=Path(sys.argv[2]).read_text().strip()))
    atv = await pyatv.connect(config, asyncio.get_running_loop())
    finished = asyncio.Event()
    class Listener:
        def playstatus_update(self, updater, playing):
            app = atv.metadata.app
            print(json.dumps({"title": playing.title, "state": playing.device_state.name,
                "app": app.identifier if app else None, "artist": playing.artist}), flush=True)
            if playing.device_state.name == "Paused":
                finished.set()
        def playstatus_error(self, updater, error):
            raise error
    listener = Listener()
    atv.push_updater.listener = listener
    atv.push_updater.start()
    try:
        await asyncio.wait_for(finished.wait(), 10)
    finally:
        atv.push_updater.stop()
        tasks = atv.close()
        if tasks:
            await asyncio.gather(*tasks)
asyncio.run(main())
