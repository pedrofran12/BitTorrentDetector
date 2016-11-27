import urllib2

class GoogleSearch(object):

    def __init__(self, toSearch):
        self.toSearch = toSearch;
        url = 'http://www.google.com/search?q='+urllib2.quote(self.toSearch)
        headers = {'User-agent':'Mozilla/11.0'}
        req = urllib2.Request(url,None,headers)
        site = urllib2.urlopen(req)
        data = site.read()
        site.close()

        #no beatifulsoup because google html is generated with javascript
        start = data.find('<div id="res">')
        end = data.find('<div id="foot">')
        if data[start:end]=='':
            self.link = None
        else:
            data = data[start:end]
            #get only results of the provided site
            start = data.find('<a href="/url?q=')
            data = data[start+len('<a href="/url?q='):]
            end = data.find('</a></h3><div class="s">')
            info =  urllib2.unquote(data[0:end])
            self.link = info.split('">', 1)

    def getTitle(self):
        try:
            return self.link[1]
        except:
            return None

    def getUrl(self):
        if self.link[0].startswith("http"):
            return self.link[0]
        else:
            return None
