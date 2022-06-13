import os

class SSLStrip:
	
	def strip(self):
		try:
			print("Performing SSL strip now...")
			os.system('sslstrip')
		except KeyboardInterrupt:
			print("Stopping SSL strip.")

if __name__ == '__main__':
    ssl = SSLStrip()
    ssl.strip()

