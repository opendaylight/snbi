package com.cisco.snbi.client;


import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

import javax.swing.JOptionPane;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;

import javax.json.*;
import javax.json.JsonValue.ValueType;
 

public class SNBIRest {
	public static String createJsonString(String[] devices, String domainName) {
		JsonBuilderFactory factory_udi = Json.createBuilderFactory(null);
		JsonArrayBuilder devices_udi = Json.createArrayBuilder();
		
        for (String x : devices) {
            devices_udi.add(factory_udi.createObjectBuilder().add("device-id",x));
        }

        JsonBuilderFactory factory_device = Json.createBuilderFactory(null);
        JsonArrayBuilder devices_list = Json.createArrayBuilder();
        devices_list.add(factory_device.createObjectBuilder().add("list-name","demo list").add("list-type","white")
        		.add("active","true").add("devices",devices_udi));
        
        JsonBuilderFactory factory_main = Json.createBuilderFactory(null);
        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        jsonBuilder.add("snbi-domain",factory_main.createObjectBuilder().add("domain-name", domainName).add("device-list",devices_list));
        JsonObject empObj = jsonBuilder.build();
        
        return empObj.toString();
	}
	
	public void connectToController(String username, String passwd, String[] devices, String registrar_ip, String domain_Name) {
	    
        try {
        	Client client = Client.create();

        	WebResource webResource = client.resource(getBaseURI());
        	webResource.addFilter(new HTTPBasicAuthFilter(username, passwd));

        	String restString = createJsonString(devices,domain_Name);
		
        	ClientResponse response = webResource.accept("application/json; charset=utf8").type("application/json").post(ClientResponse.class, restString);

        	if (response.getStatus() != 204) {
        		JOptionPane.showMessageDialog(null, "Controller Configuration is UnSuccessful");
        		
        		//throw new RuntimeException("Failed : HTTP error code : "
        		//		+ response.getStatus());
        	} else {
        		JOptionPane.showMessageDialog(null, "Controller Configuration is Successful");
        	}

        } catch (Exception e) {	
        	e.printStackTrace();
        }		
	}
	 
    private static URI getBaseURI() {
        return UriBuilder.fromUri("http://localhost:8181/restconf/config/").build();
    }
    
    public static void main(String[] args) {
    	confGui frame= new confGui();
        frame.setVisible(true);
    }

}