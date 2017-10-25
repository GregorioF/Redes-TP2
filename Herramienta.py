from scapy.all import *
import json


echoRequest = 8

timeExceed = 11

results = 0

mensajeEnviado = 0

mensajeRecibido = 1


def avg (rtt1, rtt2,rtt3):
	return (rtt1 + rtt2 + rtt3) / 3

def TomarRttPromedioYSumarloALaListaDeRecorridos(res, caminoRecorrido):
	rttPromedio = avg  (res[results][0][mensajeRecibido][IP].time - res[results][0][mensajeEnviado][IP].sent_time, 
						res[results][1][mensajeRecibido][IP].time - res[results][1][mensajeEnviado][IP].sent_time, 
						res[results][2][mensajeRecibido][IP].time - res[results][2][mensajeEnviado][IP].sent_time)

	caminoRecorrido.append({'src' : res[results][0][mensajeRecibido][IP].src, 'rtt' : rttPromedio })





def TraceRoute(ipDst = "", url = ""):
	dst = url if ipDst == "" else ipDst
	ttl = 1

	packet1 = IP(dst = dst, ttl = ttl) / ICMP( type = echoRequest)
	packet2 = IP(dst = dst, ttl = ttl) / ICMP( type = echoRequest)
	packet3 = IP(dst = dst, ttl = ttl) / ICMP( type = echoRequest)


	res = sr([packet1,packet2,packet3])
 
	caminoRecorrido = []

	while res[results][0][mensajeRecibido][ICMP].type == timeExceed :

		TomarRttPromedioYSumarloALaListaDeRecorridos(res,caminoRecorrido)

		ttl += 1
		packet1[IP].ttl  = ttl
		packet2[IP].ttl  = ttl
		packet3[IP].ttl  = ttl
		

		res = sr([packet1,packet2,packet3])


	#para tomar el rtt del ultimo mensaje que fue al destino elegido
	TomarRttPromedioYSumarloALaListaDeRecorridos(res,caminoRecorrido)


	for x in caminoRecorrido:
		print json.dumps(x)


TraceRoute(url='google.com')
