using System;
using System.Web;
using System.Collections;
using System.Collections.Generic;
using MGL.Data.DataUtilities;
using MGL.DomainModel;
using System.Security;

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //-----------------------------------------------------------------------------------------------------------------------------------------------------------------
	/// <summary>
	///
    /// MGLApplicationInterface is a singlton application variable that is used to
    /// as the single point of access for all application variables.
	///
	/// </summary>
	public sealed class MGLApplicationSecurityInterface {


        //Name that will be used as key for application object
		private static string APP_SINGLETON = "MGL_APP_SECURITY_SINGLETON";

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        //Create as a static method so this can be called using
        // just the class name (no object instance is required).
        // It simplifies other code because it will always return
        // the single instance of this class, either newly created
        // or from the application
        public static MGLApplicationSecurityInterface Instance() {
            MGLApplicationSecurityInterface appSingleton;

            //This allows us to switch which application object
            // we are using for secure/non-secure sessions
            string APPLICATION_CACHE = APP_SINGLETON;

            if (null == System.Web.HttpContext.Current.Application[APPLICATION_CACHE]) {
                //No current Application object exists, use private constructor to
                // create an instance, place it into the Application
                appSingleton = new MGLApplicationSecurityInterface();
                System.Web.HttpContext.Current.Application[APPLICATION_CACHE] = appSingleton;
            } else {
                //Retrieve the already instance that was already created
                appSingleton = (MGLApplicationSecurityInterface)System.Web.HttpContext.Current.Application[APPLICATION_CACHE];
            }

            return appSingleton;

        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
		//Private constructor so cannot create an instance
		// without using the correct method.  This is
		// this is critical to properly implementing
		// as a singleton object, objects of this
		// class cannot be created from outside this
		// class
        private MGLApplicationSecurityInterface() {
			ClearAll();
		}

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
		/// <summary>
		/// Resets all application variables to their intial values
		/// </summary>
		public void ClearAll() {

		}


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// This is the singleton application wide login configuration.
        /// </summary>
        /// <remarks>
        /// This is read from the section in the web.config, if present.
        /// </remarks>
        private LoginConfig appLoginConfig = null;

        public LoginConfig AppLoginConfig {
            get {
                return appLoginConfig;
            }
            set {
                appLoginConfig = value;
                try {
                    loginPage = AppLoginConfig.LoginPage;
                    noEntryPage = AppLoginConfig.NoEntryPage;
                } catch (Exception e) {
                    throw new Exception("Couldn't Get the default pages from the login config!", e);
                }

            }
        }




        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private ConfigurationInfo databaseConfig;

        public ConfigurationInfo DatabaseConfig {
            get {
                if (databaseConfig == null) {
                    if (AppSecurityContext.MainDbLcf != null) {
                        databaseConfig = AppSecurityContext.MainDbLcf;
                    } else {
                        Logger.LogWarning("DatabaseConfig is NULL and could not initialise it from AppSecurityContext.MainDbLcf as this is also NULL!");
                    }
                }

                return databaseConfig;
            }
            set {
                databaseConfig = value;
            }
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static string loginPage = "~/Code/Security/Login.aspx";
        public static string LoginPage {
            get { return loginPage; }
        }
        public static string noEntryPage = "~/Code/Security/DefaultNoEntry.aspx";
        public static string NoEntryPage {
            get { return noEntryPage; }
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private List<MGGroup> groups = null;
        public List<MGGroup> Groups {
            get { return groups; }
            set { groups = value; }
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private Dictionary<int, MGUser> users = null;
        public Dictionary<int, MGUser> Users {
            get { return users; }
            set { users = value; }
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private Dictionary<int, List<int>> userGroupXref = null;
        public Dictionary<int, List<int>> UserGroupXref {
            get { return userGroupXref; }
            set { userGroupXref = value; }
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private Dictionary<int, List<MGSecurityTag>> groupContentXref = null;
        public Dictionary<int, List<MGSecurityTag>> GroupContentXref {
            get { return groupContentXref; }
            set { groupContentXref = value; }
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private Dictionary<int, List<MGSecurityTag>> groupDisplayXref = null;
        public Dictionary<int, List<MGSecurityTag>> GroupDisplayXref {
            get { return groupDisplayXref; }
            set { groupDisplayXref = value; }
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private Dictionary<int, List<MGSecurityTag>> groupFunctionalityXref = null;
        public Dictionary<int, List<MGSecurityTag>> GroupFunctionalityXref {
            get { return groupFunctionalityXref; }
            set { groupFunctionalityXref = value; }
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private bool _PasswordFieldLengthChecked = false;
        public bool PasswordFieldLengthChecked
        {
            get { return _PasswordFieldLengthChecked; }
            set { _PasswordFieldLengthChecked = value; }
        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public List<SecureString> GetEmailsInGroup(string groupName) {

            // get a list of all the users emails
            List<SecureString> aUserEmails = new List<SecureString>();

            // get the group ID
            int gID = 0;
            foreach (MGGroup group in MGLApplicationSecurityInterface.Instance().Groups) {
                if ( group.Name.Equals( groupName, StringComparison.CurrentCultureIgnoreCase )) {
                    gID = group.ID;
                    break;
                }
            }

            // get the email address of all the users, if they belong to this group
            foreach( int uID in MGLApplicationSecurityInterface.Instance().Users.Keys) {

                List<int> groupIDs = null;
                MGLApplicationSecurityInterface.Instance().UserGroupXref.TryGetValue(uID, out groupIDs);

                if ( groupIDs != null && groupIDs.Contains( gID )) {
                    MGUser u;
                    MGLApplicationSecurityInterface.Instance().Users.TryGetValue( uID, out u );
                    aUserEmails.Add( u.Email );
                }
            }

            return aUserEmails;
        }



	}
}
