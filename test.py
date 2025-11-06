import asyncio
from modelscan.modelscan import ModelScan
from datetime import datetime
from modelscan.settings import DEFAULT_SETTINGS

scanner = ModelScan()

async def scan_file():
    loop = asyncio.get_event_loop()
    scan_results = await asyncio.wait_for(loop.run_in_executor(None, scanner.scan, "mod.pb"), timeout=300)
    print(scan_results)


asyncio.run(scan_file())