from scapy.all import *
import sys
from dataclasses import dataclass, field


def create_packet(stack_protocol:scapy,parameters:dict)->scapy:
    if(stack_size_check_protocol(stack_protocol,parameters)):
        save_stack_protocol = stack_protocol
        while True:
            list_attributes = parameters[stack_protocol.name]
       

            for key in list_attributes:
                if attributes_valid(key,stack_protocol):
                    setattr(save_stack_protocol[stack_protocol.name],key,parameters[stack_protocol.name][key])
                else:
                    print(f"\n{"#"*5}There were problems with the attribute [{key}] check if it is written correctly{"#"*5}\n")
                    
                    
            stack_protocol = stack_protocol.payload
            list_attributes = []
            if  stack_protocol.name== 'NoPayload':
                break
        return save_stack_protocol
    else :
        
        print("\n"+("*"*10)+"ERROR"+("*"*10))
        raise TypeError("\n 'The length of the layers is not equal to the length of the parameters'")

        
    

        
def stack_size_check_protocol(packet,parameters_modify:dict)->bool:
    if len(packet.layers()) == len(parameters_modify):
        return True
    else :
        return False
    

def attributes_valid(attribute:str,packet):
    answer = False 
    try:
       if getattr(packet,attribute):
           answer = True
       return answer
    except AttributeError:
        return answer
        
        
        
    


@dataclass
class Packet_new:
    stack_packet:Packet
    attributes_layers:dict 
    __configured_packet:Packet|None= field(default=None)
    
    
    @property
    def configured_packet(self):
        return self.__configured_packet
        

    @configured_packet.setter
    def configured_packet(self,valor):  
        self.__configured_packet = valor
        return self.__configured_packet
    
    def create_(self):
        self.configured_packet = create_packet(self.stack_packet,self.attributes_layers)
        return self.configured_packet
        
        
    
#uso de la clase Packet_new
"""stack_protocols = IP()
attributes_configure = {
    "IP":
        {
            "dst":"192.168.0.5"
        }
}
packet_new = Packet_new(stack_protocols,attributes_configure).create_()

packet_new.show()

"""
