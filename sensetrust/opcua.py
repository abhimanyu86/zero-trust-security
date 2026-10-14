import asyncio
import logging
from asyncua import Server, Client, ua
from sensetrust.plant import WaterPlant

logger = logging.getLogger(__name__)

class PlantOpcUaServer:
    def __init__(self, ca, directory, port=4840):
        self.ca = ca
        self.directory = directory
        self.port = port
        self.server = Server()
        self.plant = WaterPlant()

    async def start(self):
        await self.server.init()
        self.server.set_endpoint(f"opc.tcp://0.0.0.0:{self.port}/freeopcua/server/")
        
        # Security policies: ONLY Basic256Sha256 with SignAndEncrypt
        self.server.set_security_policy([
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt
        ])

        # Register namespace and add variables
        idx = await self.server.register_namespace("http://sensetrust/opcua/")
        objects = self.server.nodes.objects
        self.plant_obj = await objects.add_object(idx, "PlantPLC")
        
        true_readings = self.plant.true_readings()
        self.lt_node = await self.plant_obj.add_variable(idx, "LT-101", true_readings["LT-101"])
        self.pt_node = await self.plant_obj.add_variable(idx, "PT-101", true_readings["PT-101"])
        self.ft_node = await self.plant_obj.add_variable(idx, "FT-101", true_readings["FT-101"])
        self.pump_node = await self.plant_obj.add_variable(idx, "Pump", self.plant.pump)
        self.valve_node = await self.plant_obj.add_variable(idx, "Valve", self.plant.valve)

        await self.lt_node.set_writable()
        await self.pt_node.set_writable()
        await self.ft_node.set_writable()
        await self.pump_node.set_writable()
        await self.valve_node.set_writable()

        await self.server.start()

    async def stop(self):
        await self.server.stop()


class OpcUaShadowMonitor:
    def __init__(self, gw, url):
        self.gw = gw
        self.url = url

    async def run_once(self):
        client = Client(url=self.url)
        async with client:
            objects = client.nodes.objects
            plant_obj = await objects.get_child(["0:PlantPLC"])
            
            lt_val = await (await plant_obj.get_child(["0:LT-101"])).get_value()
            pt_val = await (await plant_obj.get_child(["0:PT-101"])).get_value()
            ft_val = await (await plant_obj.get_child(["0:FT-101"])).get_value()
            pump_val = await (await plant_obj.get_child(["0:Pump"])).get_value()
            valve_val = await (await plant_obj.get_child(["0:Valve"])).get_value()
            
            readings = {
                "LT-101": lt_val,
                "PT-101": pt_val,
                "FT-101": ft_val
            }
            self.gw.shadow_tick(readings, pump_val, valve_val)