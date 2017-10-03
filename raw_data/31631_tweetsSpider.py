# encoding=utf-8
import re
import requests
from lxml import etree
from scrapy_redis.spiders import RedisSpider
from Sina_spider2.weiboID import weiboID
from scrapy.selector import Selector
from scrapy.http import Request
from Sina_spider2.items import TweetsItem


class Spider(RedisSpider):
    name = "tweetsSpider"
    host = "http://weibo.cn"
    redis_key = "tweetsSpider:start_urls"
    start_urls = []
    for ID in weiboID:
        url = "http://weibo.cn/%s/profile?filter=1&page=1" % ID
        start_urls.append(url)

    def start_requests(self):
        for url in self.start_urls:
            yield Request(url=url, callback=self.parse)

    def parse(self, response):
        """ 抓取微博数据 """
        selector = Selector(response)
        ID = re.findall('weibo\.cn/(\d+)', response.url)[0]
        tweets = selector.xpath('body/div[@class="c" and @id]')
        for tweet in tweets:
            tweetsItems = TweetsItem()
            id = tweet.xpath('@id').extract_first()  # 微博ID
            content = tweet.xpath('div/span[@class="ctt"]/text()').extract_first()  # 微博内容
            cooridinates = tweet.xpath('div/a/@href').extract_first()  # 定位坐标
            like = re.findall(u'\u8d5e\[(\d+)\]', tweet.extract())  # 点赞数
            transfer = re.findall(u'\u8f6c\u53d1\[(\d+)\]', tweet.extract())  # 转载数
            comment = re.findall(u'\u8bc4\u8bba\[(\d+)\]', tweet.extract())  # 评论数
            others = tweet.xpath('div/span[@class="ct"]/text()').extract_first()  # 求时间和使用工具（手机或平台）

            tweetsItems["_id"] = ID + "-" + id
            tweetsItems["ID"] = ID
            if content:
                tweetsItems["Content"] = content.strip(u"[\u4f4d\u7f6e]")  # 去掉最后的"[位置]"
            if cooridinates:
                cooridinates = re.findall('center=([\d|.|,]+)', cooridinates)
                if cooridinates:
                    tweetsItems["Co_oridinates"] = cooridinates[0]
            if like:
                tweetsItems["Like"] = int(like[0])
            if transfer:
                tweetsItems["Transfer"] = int(transfer[0])
            if comment:
                tweetsItems["Comment"] = int(comment[0])
            if others:
                others = others.split(u"\u6765\u81ea")
                tweetsItems["PubTime"] = others[0]
                if len(others) == 2:
                    tweetsItems["Tools"] = others[1]
            yield tweetsItems
        url_next = selector.xpath(
            u'body/div[@class="pa" and @id="pagelist"]/form/div/a[text()="\u4e0b\u9875"]/@href').extract()
        if url_next:
            yield Request(url=self.host + url_next[0], callback=self.parse)
        else:  # 如果没有下一页即表示该用户的微博已经爬完了，接下来爬第一页的关注，加入待爬队列
            urlFollows = "http://weibo.cn/%s/follow" % ID
            idFollows = self.getNextID(urlFollows, response.request.cookies)
            for ID in idFollows:
                url = "http://weibo.cn/%s/profile?filter=1&page=1" % ID
                yield Request(url=url, callback=self.parse)

    def getNextID(self, url, cookies):
        """ 打开url爬取里面的个人ID """
        IDs = []
        r = requests.get(url=url, cookies=cookies)
        if r.status_code == 200:
            selector = etree.HTML(r.content)
            texts = selector.xpath(
                u'body//table/tr/td/a[text()="\u5173\u6ce8\u4ed6" or text()="\u5173\u6ce8\u5979"]/@href')
            IDs = re.findall('uid=(\d+)', ";".join(texts), re.S)
        return IDs
