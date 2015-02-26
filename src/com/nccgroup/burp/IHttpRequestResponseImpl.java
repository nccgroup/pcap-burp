/* 
 * Released as open source by NCC Group Plc - https://www.nccgroup.com/
 *
 * Developed by Stephen Tomkinson, stephen.tomkinson@nccgroup.com
 * 
 * https://www.github.com/nccgroup/pcap-burp
 *
 * Licensed under the Affero General Public License 
 * https://github.com/nccgroup/pcap-burp/LICENSE
 */
package com.nccgroup.burp;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class IHttpRequestResponseImpl implements IHttpRequestResponse {

	private byte[] request;
	private byte[] response;
	private String comment;
	private String highlight;
	private IHttpService httpService;
	
	public IHttpRequestResponseImpl(byte[] request, byte[] response) {
		super();
		this.request = request;
		this.response = response;
	}

	public byte[] getRequest() {
		return request;
	}

	public void setRequest(byte[] message) {
		this.request = message;
	}

	public byte[] getResponse() {
		return response;
	}

	public void setResponse(byte[] message) {
		this.response = message;
	}

	public String getComment() {
		return comment;
	}

	public void setComment(String comment) {
		this.comment = comment;
	}

	public String getHighlight() {
		return highlight;
	}

	public void setHighlight(String color) {
		this.highlight = color;
	}

	public IHttpService getHttpService() {
		return httpService;
	}

	public void setHttpService(IHttpService httpService) {
		this.httpService = httpService;
	}

}
