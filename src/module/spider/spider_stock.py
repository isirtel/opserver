#coding=utf-8
import urllib
import re
import os
import urllib.request
import MySQLdb
import csv
import codecs
import time

class stock_store():
    def __init__(self):
      self.code_list=[]
      self.start=""
      self.end=""
      self.tmp_file_path = "/tmp/"
      self.db = MySQLdb.connect("localhost", "isir", "isir", "isir", charset='utf8' )
      self.cursor = self.db.cursor()
    def get_stock_code(self):

        sql = "select stock_code from stock_spider;"
        try:
           self.cursor.execute(sql)
           results = self.cursor.fetchall()
           for row in results:
              stock_code = row[0]
              if stock_code is None:
                continue
              self.code_list.append(stock_code)
        except:
           print ("get stock info failed")
    def get_stock_info(self, start, end, compare):
        for code in self.code_list:
           url=""
           if code[0] == '0':
                url = 'http://quotes.money.163.com/service/chddata.html?code=1%s'%(code)+\
                    '&start='+start+'&end='+end+'&fields=TCLOSE;HIGH;LOW;TOPEN;LCLOSE;CHG;PCHG;TURNOVER;VOTURNOVER;VATURNOVER;TCAP;MCAP'
           else:
                url = 'http://quotes.money.163.com/service/chddata.html?code=0%s'%(code)+\
                    '&start='+start+'&end='+end+'&fields=TCLOSE;HIGH;LOW;TOPEN;LCLOSE;CHG;PCHG;TURNOVER;VOTURNOVER;VATURNOVER;TCAP;MCAP'

           path = self.tmp_file_path+'%s'%code+'.csv'
           print(start)
           print(url)
           urllib.request.urlretrieve(url, path)
           f = codecs.open(path, 'r+', 'gbk')
           reader = csv.reader(f)
           header = next(reader)
           sql = ""

           for row in reader:
             i = 0
             while i < 15:
                if row[i] is None or row[i] == "None":
                    row[i]='0'
                i = i+1
             sql = "insert into stock_info (sdate,stock_code,name,closing_price,highest,lowest_price,opening,before_closing,"\
             "rise_fall_forehead,applies,turnover_rate,volume,clinch_deal_amount,total_market_value,current_market) values"\
             "('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s');"\
             %(row[0],row[1][1:],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10],row[11],row[12],row[13],row[14])
             
             print(sql)
             self.cursor.execute(sql)
           f.close()
           os.remove(path) 
        self.db.commit()
        self.db.close()

if __name__ == '__main__':


    stock = stock_store()
    stock.get_stock_code()
    sql = "select sdate from stock_info order by sdate desc limit 1;"
    stock.cursor.execute(sql)
    row = stock.cursor.fetchone()
    sdate1 = row[0]
    sdate = sdate1.split('-');
    t_start = ""
    for item in sdate:
        t_start = t_start+item
    time_ask = time.strftime("%Y%m%d", time.localtime()) 
    stock.get_stock_info(t_start, time_ask, sdate1)
    


