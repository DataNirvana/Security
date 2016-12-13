using System;
using System.Web;
using System.Collections;
using System.Reflection;
using MGL.DomainModel;
using MGL.Data.DataUtilities;
using System.Text;
//using MGL.LLPG;


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //--------------------------------------------------------------------------------------------------------------------------------------------------------------
	/// <summary>
	///
	/// SessionInterface is a singlton session variable that is used to
	/// as the single point of access for all session variables.
	///
	/// </summary>
	public sealed class MGLSessionSecurityInterface {
		//Name that will be used as key for Session object
		private static string SESSION_SINGLETON = "MGL_SESS_SECURITY_SINGLETON";

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
		//Create as a static method so this can be called using
		// just the class name (no object instance is required).
		// It simplifies other code because it will always return
		// the single instance of this class, either newly created
		// or from the session
		public static MGLSessionSecurityInterface Instance() {
			MGLSessionSecurityInterface seshSingleton = null;

            try {
                if (System.Web.HttpContext.Current != null && System.Web.HttpContext.Current.Session != null) {
                    if (null == System.Web.HttpContext.Current.Session[SESSION_SINGLETON]) {
                        //No current session object exists, use private constructor to
                        // create an instance, place it into the session
                        seshSingleton = new MGLSessionSecurityInterface();
                        System.Web.HttpContext.Current.Session[SESSION_SINGLETON] = seshSingleton;
                    } else {
                        //Retrieve the already instance that was already created
                        seshSingleton = (MGLSessionSecurityInterface)System.Web.HttpContext.Current.Session[SESSION_SINGLETON];
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(7, "MGLSessionSecurityInterface crashed when access was attempted: " + ex.ToString());
            }

			return seshSingleton;
		}


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        //Private constructor so cannot create an instance
        // without using the correct method.  This is
        // this is critical to properly implementing
        // as a singleton object, objects of this
        // class cannot be created from outside this
        // class
        private MGLSessionSecurityInterface() {
            //Intialise the vars
            ClearAll();
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Resets all session variables to their intial values
        /// </summary>
        public void ClearAll() {
//            config = null;
            currentUser = null;
            securityError = null;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private MGUser currentUser = null;
        public MGUser CurrentUser {
            get { return currentUser; }
            set { currentUser = value; }
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private string securityError = null;
        public string SecurityError {
            get { return securityError; }
            set { securityError = value; }
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private string userIPAddress = null;
        public string UserIPAddress {
            get { return userIPAddress; }
            set { userIPAddress = value; }
        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private StringBuilder saltLogin;
        public StringBuilder SaltLogin {
            get { return saltLogin; }
            set { saltLogin = value; }
        }
        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private StringBuilder saltPasswordReset;
        public StringBuilder SaltPasswordReset {
            get { return saltPasswordReset; }
            set { saltPasswordReset = value; }
        }
        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private StringBuilder saltPasswordRequestReset;
        public StringBuilder SaltPasswordRequestReset {
            get { return saltPasswordRequestReset; }
            set { saltPasswordRequestReset = value; }
        }
        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private StringBuilder saltPasswordChange;
        public StringBuilder SaltPasswordChange {
            get { return saltPasswordChange; }
            set { saltPasswordChange = value; }
        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Use HTTPS in a specific session for public facing sites with an admin component like the Explore.RAHAPakistan.org website ...
        /// </summary>
        //public bool UseHTTPS {
        //    get { return useHTTPS; }
        //    set { useHTTPS = value; }
        //}
        //private bool useHTTPS = false;


	}
}
