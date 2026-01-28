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
                    dict_new = create_dic()
                    create_packet(stack_protocol,dict_new)
                    
            stack_protocol = stack_protocol.payload
            list_attributes = []
            if  stack_protocol.name== 'NoPayload':
                break
        return save_stack_protocol
    else :
        
        print("\n"+("*"*10)+"ERROR"+("*"*10))
        raise TypeError("\n 'The length of the layers is not equal to the length of the parameters'")

        
    
    
def create_dic()->dict:
    counter_layer = int(input("How many layers will the protocol stack have? -> "))
    counter = 0

    dict = {}
    while  counter< counter_layer:
        print("********************************************************************************+")
        name_layer = input("enter the layer name -> ").upper()
        number_parameters = int(input("enter the  parameters number ->"))
        dict[name_layer]= {}
        
        while number_parameters > 0:
            print("*************************************************")
            name_parameter = input("enter the parameter name -> ")
            value_parameter = input("enter the parameter value -> ")
            type_of_value_the_attribute = input("What is the data TYPE of the entered value? -> ")
            if type_of_value_the_attribute == "int":
                value_parameter = int(value_parameter)
            dict[name_layer][name_parameter] = value_parameter
            number_parameters -= 1
        counter += 1
    
    return dict
        
        
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
    attributes_layers:dict = field(default_factory=create_dic)
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
        
        
    
    
  
    
    
    
    
    

stack_protocols = IP()

packet_new = Packet_new(stack_protocols).create_()

packet_new.show()


#packet_set = create_packet(packet, create_dic())

