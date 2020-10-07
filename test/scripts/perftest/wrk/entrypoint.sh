#!/bin/bash                                                                
                                                                           
echo "This is a idle script (infinite loop) to keep container running."    
echo "Please replace this script."                                         
                                                                           
cleanup ()                                                                 
{                                                                          
  kill -s SIGTERM $!                                                         
  exit 0                                                                     
}                                                                          
                                                                           
trap cleanup SIGINT SIGTERM                                                
                                                                           
while [ 1 ]                                                                
do                                                                         
  sleep 60 &                                                             
  wait $!                                                                
done