import sqlite3
import socket
import os
import json

class Database:
    def __init__(self, db_name='noise.db'):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS runtime (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            count INTEGER, 
            duration INTEGER, 
            updatetime INTEGER, 
            maxtime INTEGER, 
            cpu INTEGER, 
            type TEXT);
        ''')

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS sample (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            count INTEGER, 
            duration INTEGER, 
            updatetime INTEGER, 
            period INTEGER,
            threshold INTEGER,
            maxsingle INTEGER,
            hardware INTEGER,
            noisetime INTEGER,
            cpu INTEGER);
        ''')
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()


class Server:
    def __init__(self, address='/tmp/unix_socket_mockbmcserver'):
        self.server_address = address
        if os.path.exists(self.server_address):
            os.unlink(self.server_address)
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(1)
        print('wait for clients...')

    def accept_connection(self):
        return self.server_socket.accept()

    def close(self):
        self.server_socket.close()



class Controller:
    def __init__(self):
        self.db = Database()
        self.server = Server()

    def process_data(self, data):

        print('recv:', data.decode())
        try:
            message = json.loads(data.decode())
            if "uici" in message:
                print(message)
                # {"uici":[{"cpu":0,"count":1570,"max_time":141742,"hardware":-12348484,"nmi":494,"irq":184030,"softirq":12106802,"thread":58728}]}
                arr = message["uici"]
                for obj in arr:
                    command = obj["command"]
                    action = obj["action"]
                    type=obj["type"]
                    if command == "sql":
                        if action == "nc-query":
                            if type == "latest":
                                self.latest()
                            else:
                                self.empty()
                        elif action == "nc-upload":
                            if type == "sample":
                                self.insert_sample(obj)
                            else:
                                self.insert_trace(obj)
                            pass

        except json.JSONDecodeError:
            print("Invalid JSON received")
    
    def latest(self):

        try:
            sql='''
            SELECT 
                s.cpu, 
                s.updatetime AS TIMESTAMP, 
                s.duration AS RUNTIE_IN_NS, 
                s.noisetime AS NOISE_IN_NS,
                ROUND(CAST((s.duration - s.noisetime) AS REAL) / s.duration * 100, 5) AS CPU_AVAILABLE,
                s.maxsingle AS MAX_SINGLE_NOISE,
                COALESCE(MAX(CASE WHEN r.type = 'irq' THEN r.count END), 0) AS irq,
                COALESCE(MAX(CASE WHEN r.type = 'nmi' THEN r.count END), 0) AS nmi,
                COALESCE(MAX(CASE WHEN r.type = 'softirq' THEN r.count END), 0) AS softirq,
                COALESCE(MAX(CASE WHEN r.type = 'thread' THEN r.count END), 0)AS thread,
                s.count
            FROM 
                sample s 
            LEFT JOIN 
                runtime r ON s.cpu = r.cpu AND s.updatetime = r.updatetime 
            GROUP BY 
                s.id, s.count, s.duration, s.updatetime, s.period, s.cpu, s.threshold 
            order by s.updatetime  desc
            '''
            self.db.cursor.execute(sql)
            result = self.db.cursor.fetchall()
            for row in result:
                print(row)
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in query: {e}")
        pass
        print("")

    def empty(self):
        print("")

    def insert_trace(self, obj):
        if not obj["type"] or len(obj["type"]) <= 0:
            return
        
        cpu = obj["cpu"]
        count = obj["count"]
        duration = obj["duration"]
        updatetime = obj["updatetime"]
        maxtime = obj["maxtime"]
        type = obj ["type"]

        sql = """
            INSERT INTO runtime (cpu, count, duration, updatetime, maxtime, type) 
            VALUES (?, ?, ?, ?, ?, ?);
        """

        try:
            self.db.cursor.execute(sql, (cpu, count, duration, updatetime, maxtime, type))
            self.db.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in insert_trace {e}")
        pass

        print("done insert trace")

    def insert_sample(self, obj):
        cpu = obj["cpu"]
        count = obj["count"]
        updatetime = obj["updatetime"]
        duration = obj["duration"]
        period = obj["period"]
        threshold = obj["threshold"]
        maxsingle = obj["maxsingle"]
        hardware = obj["hardware"]
        noisetime = obj["noisetime"]

        sql = """
            INSERT INTO sample (cpu, count, updatetime, duration, period, threshold, maxsingle, hardware, noisetime) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        try:
            self.db.cursor.execute(sql, (cpu, count, updatetime, duration, period, threshold, maxsingle, hardware, noisetime))
            self.db.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in insert_sample: {e}")
        pass

    def run(self):
        while True:
            connection, client_address = self.server.accept_connection()
            try:
                print('客户端连接:', client_address)
                while True:
                    data = connection.recv(1024)
                    if data:
                        self.process_data(data)
                    else:
                        break
            finally:
                connection.close()

    def close(self):
        if hasattr(self, 'db'):
            self.db.close()
        if hasattr(self, 'server'):
            self.server.close()

if __name__ == '__main__':
    controller = Controller()
    try:
        controller.run()
    except KeyboardInterrupt:
        print("shutdown ...")
    finally:
        controller.close()
