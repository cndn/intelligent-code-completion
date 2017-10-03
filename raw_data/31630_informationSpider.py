# encoding=utf-8
import re
import datetime
import requests
from lxml import etree
from scrapy_redis.spiders import RedisSpider
from Sina_spider2.weiboID import weiboID
from scrapy.selector import Selector
from scrapy.http import Request
from Sina_spider2.items import InformationItem


class Spider(RedisSpider):
    name = "informationSpider"
    host = "http://weibo.cn"
    redis_key = "informationSpider:start_urls"
    start_urls = []
    for ID in weiboID:
        url = url_information1 = "http://weibo.cn/%s/info" % ID
        start_urls.append(url)

    def start_requests(self):
        for url in self.start_urls:
            yield Request(url=url, callback=self.parse)

    def parse(self, response):
        informationItems = InformationItem()
        selector = Selector(response)
        ID = re.findall('weibo\.cn/(\d+)', response.url)[0]
        text1 = ";".join(selector.xpath('body/div[@class="c"]/text()').extract())  # 获取标签里的所有text()
        nickname = re.findall(u'\u6635\u79f0[:|\uff1a](.*?);', text1)  # 昵称
        gender = re.findall(u'\u6027\u522b[:|\uff1a](.*?);', text1)  # 性别
        place = re.findall(u'\u5730\u533a[:|\uff1a](.*?);', text1)  # 地区（包括省份和城市）
        signature = re.findall(u'\u7b80\u4ecb[:|\uff1a](.*?);', text1)  # 个性签名
        birthday = re.findall(u'\u751f\u65e5[:|\uff1a](.*?);', text1)  # 生日
        sexorientation = re.findall(u'\u6027\u53d6\u5411[:|\uff1a](.*?);', text1)  # 性取向
        marriage = re.findall(u'\u611f\u60c5\u72b6\u51b5[:|\uff1a](.*?);', text1)  # 婚姻状况
        url = re.findall(u'\u4e92\u8054\u7f51[:|\uff1a](.*?);', text1)  # 首页链接

        informationItems["_id"] = ID
        if nickname:
            informationItems["NickName"] = nickname[0]
        if gender:
            informationItems["Gender"] = gender[0]
        if place:
            place = place[0].split(" ")
            informationItems["Province"] = place[0]
            if len(place) > 1:
                informationItems["City"] = place[1]
        if signature:
            informationItems["Signature"] = signature[0]
        if birthday:
            try:
                birthday = datetime.datetime.strptime(birthday[0], "%Y-%m-%d")
                informationItems["Birthday"] = birthday - datetime.timedelta(hours=8)
            except Exception:
                pass
        if sexorientation:
            if sexorientation[0] == gender[0]:
                informationItems["Sex_Orientation"] = "gay"
            else:
                informationItems["Sex_Orientation"] = "Heterosexual"
        if marriage:
            informationItems["Marriage"] = marriage[0]
        if url:
            informationItems["URL"] = url[0]

        urlothers = "http://weibo.cn/attgroup/opening?uid=%s" % ID
        r = requests.get(urlothers, cookies=response.request.cookies)
        if r.status_code == 200:
            selector = etree.HTML(r.content)
            texts = ";".join(selector.xpath('//body//div[@class="tip2"]/a//text()'))
            if texts:
                num_tweets = re.findall(u'\u5fae\u535a\[(\d+)\]', texts)  # 微博数
                num_follows = re.findall(u'\u5173\u6ce8\[(\d+)\]', texts)  # 关注数
                num_fans = re.findall(u'\u7c89\u4e1d\[(\d+)\]', texts)  # 粉丝数
                if num_tweets:
                    informationItems["Num_Tweets"] = int(num_tweets[0])
                if num_follows:
                    informationItems["Num_Follows"] = int(num_follows[0])
                if num_fans:
                    informationItems["Num_Fans"] = int(num_fans[0])
        yield informationItems

        urlFollows = "http://weibo.cn/%s/follow" % ID  # 爬第一页的关注，加入待爬队列
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
