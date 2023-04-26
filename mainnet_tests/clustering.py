#!/usr/bin/python
# -*- coding: UTF-8 -*-
import pandas as pd
import datetime
from crawl_nodes import code_ip, connect_db, root_path
from models import Node
from sqlalchemy import and_


if __name__ == "__main__":
    starttime = datetime.datetime.now()
    session = connect_db()
    q = session.query(Node).filter(
        and_(Node.date == datetime.datetime.now().strftime("%Y-%m-%d")))
    nodes = pd.read_sql(q.statement, q.session.bind)
    # nodes.groupby(['version', 'user_agent', 'services', 'sync_rate']).count().to_csv("tests/eval_calsize.xlsx")
    nodes.set_index(['version','user_agent', 'services','sync_rate'],inplace=True)
    nodes.sort_index(level=1,inplace=True)
    nodes.to_excel("tests/eval_size.xlsx")
    print(nodes)
    # ['version', 'user_agent', 'services', 'blocksync_rate']
    endtime = datetime.datetime.now()
    print('耗时：' + str((endtime - starttime).seconds) + 's')
