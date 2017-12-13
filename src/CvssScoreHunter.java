import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.jsoup.Jsoup;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.File;
import java.io.IOException;

public class CvssScoreHunter {

	public static void main(String[] args) {
			Scanner scan = new Scanner(System.in);
			String pathToFile = " ";
			String proxy = null;
			int proxyPort = 0;
			String proxyUser = null;
			String proxyPass = null;
			String userProxy = null;
			boolean isProxy = false;

			try {
				System.out.print("Enter path/to/HTML/report: ");
				pathToFile = scan.next();
				System.out.print("Proxy? (y/n): ");
				userProxy = scan.next();
				
				if(userProxy.equalsIgnoreCase("y")) {
					isProxy = true;
					System.out.print("Proxy Host: ");
					proxy = scan.next();
					System.out.print("Proxy Port: ");
					proxyPort = scan.nextInt();
					System.out.print("Credentials required? (y/n): ");
					String requireCreds = scan.next();
					if(requireCreds.equalsIgnoreCase("y")) {
						System.out.print("Proxy User: ");
						proxyUser = scan.next();
						System.setProperty("http.proxyUser", proxyUser);
						System.out.print("Proxy Password: ");
						proxyPass = scan.next();
						System.setProperty("http.proxyPassword", proxyPass);
					}
				}
				
			} catch(Exception e) {
				e.printStackTrace();
			} finally {
				scan.close();
			}
			//Get HTML Document
			Document doc = getDepCheckDoc(pathToFile);
			Elements tr = doc.getElementsByAttributeValue("class", "vulnerable");
			//Fine all <a> tags
			Elements aTag = doc.getElementsByTag("a");
			//Get links!
			List<String> cveLinks = getLinks(aTag, tr);
			
			for(String link : cveLinks) {
				try {
					if(isProxy = true && proxy != null && proxyPort != 0) {
						Document cveDoc = Jsoup.connect(link)
								.proxy(proxy, proxyPort)
								.timeout(10000)
								.userAgent("Mozilla/5.0 (Windows; U; WindowsNT 5.1; en-US; rv1.8.1.6) Gecko/20070725 Firefox/2.0.0.6")
								.referrer("http://www.google.com")
								.validateTLSCertificates(false)
								.followRedirects(true)
								.get();
						
						getCvssScores(cveDoc);
					}
					else {
						Document cveDoc = Jsoup.connect(link)
								.timeout(10000)
								.userAgent("Mozilla/5.0 (Windows; U; WindowsNT 5.1; en-US; rv1.8.1.6) Gecko/20070725 Firefox/2.0.0.6")
								.referrer("http://www.google.com")
								.validateTLSCertificates(false)
								.followRedirects(true)
								.get();
						
						getCvssScores(cveDoc);
					}
					
				} 
				catch (Exception e) {
					e.printStackTrace();
				}
			}
	}
	
	//Parses the dependency check report
	public static Document getDepCheckDoc(String file) {
		Document doc = null;
		if(file != " " || file != null) {
			File depCheckHtmlExport = new File(file);
			
			try {
				doc = Jsoup.parse(depCheckHtmlExport, "UTF-8", "http://example.com/");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return doc;
	}	
	
	//Parses the NVD CVE detail page
	public static Document getCvssScores(Document cveDoc) {
		if(cveDoc != null) {
			Elements dl = cveDoc.getElementsByTag("dl");

			for(Element dd : dl) {
				Elements dtTag = dd.getElementsByTag("dt");
				Elements aTag = dd.getElementsByTag("a");
				Elements spanTag = dd.getElementsByTag("span");
				
				for(Element dt : dtTag) {
					if(dt.text().equals("CVSS v2 Base Score:")) {
						System.out.print(dt.text());
					}
				}
				for(Element a : aTag) {
					if(a.attr("data-testid").contains("vuln-cvssv2-base-score-link")) {
						System.out.print(" " + a.text());
					}
				}
				
				for(Element s : spanTag) {
					if(s.attr("data-testid").contains("vuln-cvssv2-base-score-severity")) {
							System.out.println(" " + s.text().toUpperCase());
					}
				}
				
				for(Element dt : dtTag) {
					if(dt.text().equals("CVSS v3 Base Score:")) {
						System.out.print(dt.text());
					}
				}
				for(Element a : aTag) {
					if(a.attr("data-testid").contains("vuln-cvssv3-base-score-link")) {
						System.out.print(" " + a.text());
					}
				}
				
				for(Element s : spanTag) {
					if(s.attr("data-testid").contains("vuln-cvssv3-base-score-severity")) {
						System.out.println(" " + s.text());
					}
				}
				
			}
			
			System.out.println("");
		}

		return cveDoc;
	}	
    public static List<String> getLinks(Elements a, Elements tr) {
	    	List<String> links = new ArrayList<String>();
	    	//String string = null;
	    	//String name = null;
	    	
	    	int count = 0;
	    	
	    	for (Element header : tr) {
	    		header.getElementsByAttribute("a");
	    	}
	    	 for (Element el : a) {  
	        	 	if(el.attr("href") != null && !el.attr("href").isEmpty()) {
	        	 		if(el.attr("href").contains("http://web.nvd.nist.gov/view/vuln/detail?vulnId=")) {
	        	 			//System.out.println(el.parent().parent().getElementsByAttributeValueContaining("onclick", "copyText"));
	        	 			//string = el.parent().parent().getElementsByAttributeValueContaining("onclick", "copyText").toString();
	        	 			//System.out.println(string);
	        	 			//parts = string.split("\\s+");
	        	 			//System.out.println(parts[13]);
	        	 			
	        	 			links.add(el.attr("href"));
	        	 			//System.out.println(el.attr("href"));
		        	 		count++;
	        	 		}
	        	 	}
	         }
	    	 System.out.println(count + " Links(s) identified...");
	    	 System.out.println("Hunting...");
	    	 System.out.println("");
	    	 return links;
    }
    

}
