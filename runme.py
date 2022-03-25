import asyncio
import sys

import logging
logging.basicConfig(level=logging.DEBUG)

sys.path.append(".")
import openssh.aio




async def runme():

    ssh = openssh.aio.SSH("localhost")

    await ssh.connect()

    await ssh.open_ex("echo hello world")
    #print(await ssh.run("uname -a"))


asyncio.run(runme())

