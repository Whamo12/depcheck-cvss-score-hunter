import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Spliterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jsoup.Connection.Response;
import org.jsoup.Jsoup;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CvssScoreHunter {

	public static void main(String[] args) {
			Scanner scan = new Scanner(System.in);
			String pathToFile = " ";
			
			try {
				Path currentRelativePath = Paths.get("");
				String s = currentRelativePath.toAbsolutePath().toString();
				pathToFile = scan.next();
			} catch(Exception e) {
				e.printStackTrace();
			} finally {
				scan.close();
			}
			//Get HTML Document
			Document doc = getDepCheckDoc(pathToFile);
			Elements tr = doc.getElementsByAttributeValue("class", "vulnerable");
			//Find all vuln libraries
			Elements h3Tag = doc.getElementsByTag("h3");
			//Fine all <a> tags
			Elements aTag = doc.getElementsByTag("a");
			//Get links!
			List<String> cveLinks = getLinks(aTag, tr);
			
			for(String link : cveLinks) {
				try {
					Document cveDoc = Jsoup.connect(link).timeout(300000)
							.userAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_16) Gecko/20100101 Firefox/25.0")
							.referrer("http://www.google.com")
							.validateTLSCertificates(false).get(); 
					
					getCvssScores(cveDoc);
				} catch (Exception e) {
					
				}
				//System.out.println("Link: " + link);
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
			Elements h1Tags = cveDoc.getElementsByTag("h1");
			
			for(Element h : h1Tags) {
				if(h.hasAttr("data-testid")) {
					System.out.println(h.text().replace("Detail", ""));
				}
			}

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
	    	List<String> headers = new ArrayList<String>();
	    	String string = null;
	    	String name = null;
	    	String[] parts = null;
	    	
	    	int count = 0;
	    	
	    	for (Element header : tr) {
	    		header.getElementsByAttribute("a");
	    	}
	    	 for (Element el : a) {  
	        	 	if(el.attr("href") != null && !el.attr("href").isEmpty()) {
	        	 		if(el.attr("href").contains("http://web.nvd.nist.gov/view/vuln/detail?vulnId=")) {
	        	 			//System.out.println(el.parent().parent().getElementsByAttributeValueContaining("onclick", "copyText"));
	        	 			string = el.parent().parent().getElementsByAttributeValueContaining("onclick", "copyText").toString();
	        	 			//System.out.println(string);
	        	 			parts = string.split("\\s+");
	        	 			//System.out.println(parts[13]);
	        	 			
	        	 			links.add(el.attr("href"));
	        	 			//System.out.println(el.attr("href"));
		        	 		count++;
	        	 		}
	        	 	}
	         }
	    	 System.out.println(count + " Links(s) identified...");
	    	 System.out.println("Hunting...");
	    	 return links;
    }
    

}
