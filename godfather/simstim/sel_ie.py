import random
import selenium
import sys
import time
import ctypes

from selenium import webdriver


# load library
hypercall = ctypes.cdll.LoadLibrary('hypercall.dll')

if len(sys.argv) < 2:
    print "Usage: %s lista" % sys.argv[0]
    sys.exit(2)

lista = ["http://"+x for x in open(sys.argv[1]).read().split("\n")]

# Create a new instance of the IE WebDriver
print " [*] opening IE"
driver = webdriver.Ie()
#driver = webdriver.Firefox()
# Set 1minute timeout on loading
driver.set_page_load_timeout(60)

i = 1
while True:
    try:
        index = random.randint(0, len(lista))
        site = lista[index]
        print " [*] Visiting %s %d" % (site, i)
        # Notify hypervisor we are visiting
        try: 
            hypercall.hypercall_visit(site)
        except WindowsError:
            print "hypervisor?"

        driver.get(site)
        ii = 0
        for webelem in driver.find_elements_by_tag_name("a"):
            try:
                if (webelem.text != "" and webelem.is_displayed() and webelem.is_enabled()
                    and webelem.get_attribute("href") != ""):
                    print " [*] Click on %s" % webelem.get_attribute("href")
                    try: 
                        hypercall.hypercall_visit(webelem.get_attribute("href").encode("ascii"))
                    except WindowsError:
                        print "hypervisor?"

                    webelem.click()
            except Exception, e:
                pass
            finally:
                if ii > 2:
                    break
                ii += 1

        print " [*] Sleeping some time to sim user..."
        time.sleep(300)
        print " [*] Done!"
    except Exception, e:
        print e.__str__()
        pass
    i += 1

