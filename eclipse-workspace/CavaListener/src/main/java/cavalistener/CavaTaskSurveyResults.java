package cavalistener;

/**
 * A set of survey results.
 * 
 * @author Sunny J. Fugate
 */
public class CavaTaskSurveyResults {

	protected boolean isCompleted = false;
	
	CavaTask cavaTask;
	
	public String question1;
	public String response1;
	public String scale1;
	public String comment1;
	
	public String question2;
	public String response2;
	public String scale2;
	public String comment2;
	
	public String question3;
	public String response3;
	public String scale3;
	public String comment3;
	
	/**
	 * Constructor taking the CAVA task details for which
	 * this survey concerns. 
	 * 
	 * @param cavaTask
	 */
	public CavaTaskSurveyResults(CavaTask cavaTask) {
		this.cavaTask = cavaTask;
	}
	
	/**
	 * Sets the values for question 1
	 * @param question
	 * @param response
	 * @param comment
	 * @param scale
	 */
	public void setQ1(String question, String response, String comment, String scale) {
		question1=question;
		response1=response;
		scale1=scale;
		comment1=comment;
	}
	
	/**
	 * Sets the values for question 2
	 * @param question
	 * @param response
	 * @param comment
	 * @param scale
	 */
	public void setQ2(String question, String response, String comment, String scale) {
		question2=question;
		response2=response;
		scale2=scale;
		comment2=comment;
	}
	
	/**
	 * Sets the values for question 3
	 * @param question
	 * @param response
	 * @param comment
	 * @param scale
	 */
	public void setQ3(String question, String response, String comment, String scale) {
		question3=question;
		response3=response;
		scale3=scale;
		comment3=comment;
	}
}
