using System;
using System.Web;
using System.Xml;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// A config section handler for the login.Config section
    /// which sets up the application login options.
    /// </summary>
    public class LoginConfig : IConfigurationSectionHandler {

        /// <summary>
        /// The entries in the login config section as (string) key/value pairs.
        /// </summary>
        private readonly NameValueCollection entries = new NameValueCollection();

        /// <summary>
        /// The section in the web.config containing the login config info.
        /// </summary>
        public static string SECTION_NAME = "loginConfig";

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// The singleton instance of the application LoginConfig.
        /// </summary>
        public static LoginConfig Instance {
            get {
                return (LoginConfig) ConfigurationManager.GetSection(SECTION_NAME);
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Create the cfg section handler when called by the framework.
        /// </summary>
        object IConfigurationSectionHandler.Create(object parent, object configContext, XmlNode section) {
            return (object) new LoginConfig(parent, configContext, section);
        }

        #region Constructors

        private LoginConfig() { /* NOP. */ }

        /// <summary>
        /// Create a login config section handler using the given input.
        /// </summary>
        public LoginConfig(object parent, object configContext, XmlNode section)
        {
            try
            {
                XmlElement entriesElement = section["entries"];
                foreach (object obj in entriesElement)
                {
                    if (obj != null && obj is XmlElement)
                    {
                        XmlElement element = obj as XmlElement;
                        if (element != null && element.HasAttributes)
                        {
                            entries.Add(element.Attributes["key"].Value, element.Attributes["value"].Value);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new System.Configuration.ConfigurationErrorsException("Error while parsing configuration section.", ex, section);
            }
        }

        #endregion

        #region Properties

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// The login.Config entries.
        /// </summary>
        public NameValueCollection Map {
            get { return entries; }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// The login page which users are routed to if login is mandated.
        /// </summary>
        public string LoginPage {
            get {
                return Map["LoginPage"];
            } set {
                Map["LoginPage"] = value;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// The No Entry Page which users are routed to if login is mandated.
        /// </summary>
        public string NoEntryPage {
            get {
                return Map["NoEntryPage"];
            }
            set {
                Map["NoEntryPage"] = value;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// If this is true the system will use mgl encryption on user passwords
        /// This means we will be able to decrypt passwords for the
        /// Password reminder functionality
        /// </summary>
        public bool UseMGLRatherThanMySQLPasswordEncryption
        {
            get
            {
                return Convert.ToBoolean(Map["UseMGLRatherThanMySQLPasswordEncryption"]);
            }
            set
            {
                Map["UseMGLRatherThanMySQLPasswordEncryption"] = value.ToString();
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// This is the page that contains the user registration control.
        /// </summary>
        public string RegistrationPageURL
        {
            get
            {
                return Map["RegistrationPageURL"];
            }
            set
            {
                Map["RegistrationPageURL"] = value;
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// This is the default page that a user will be sent to after logging in,
        /// if no other post login page is specified in the nextPage query string variable.
        /// </summary>
        public string DefaultPostLoginPage{
            get {
                return Map["DefaultPostLoginPage"];
            } set {
                Map["DefaultPostLoginPage"] = value;
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// The location of the T & C page.
        /// </summary>
        public bool ShowTermsAndConditions {
            get {
                return Convert.ToBoolean(Map["ShowTermsAndConditions"]);
            } set {
                Map["ShowTermsAndConditions"] = value.ToString();
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// The location of the T & C page.
        /// </summary>
        public string TermsAndConditionsURL {
            get {
                return Map["TermsAndConditions"];
            }
            set {
                Map["TermsAndConditions"] = value.ToString();
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// If true, the login checking will be completely bypassed.
        /// Useful for debugging or unsecured sites.
        /// </summary>
        public bool BypassLogin {
            get {
                return Convert.ToBoolean(Map["BypassLogin"]);
            } set {
                Map["BypassLogin"] = value.ToString();
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Flag indicates if guests are allowed. If so,
        /// the unsecure pages can be viewed under a guest account.
        /// If not logged in as guest the user will be presented
        /// with a login page that has a 'login as guest' link.
        /// Thereafter, unsecure pages can be viewed.
        /// </summary>
        public bool AllowGuests {
            get {
                return Convert.ToBoolean(Map["AllowGuests"]);
            } set {
                Map["AllowGuests"] = value.ToString();
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Flag indicates if new users can register.
        /// If so, the login page has a register link
        /// that allows this.
        /// </summary>
        public bool AllowRegistration {
            get {
                return Convert.ToBoolean(Map["AllowRegistration"]);
            } set {
                Map["AllowRegistration"] = value.ToString();
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// </summary>
        public bool EnableAutomatedLogin {
            get {
                return Convert.ToBoolean(Map["EnableAutomatedLogin"]);
            } set {
                Map["EnableAutomatedLogin"] = value.ToString();
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// </summary>
        public bool SecureFrontPage {
            get {
                return Convert.ToBoolean(Map["SecureFrontPage"]);
            }
            set {
                Map["SecureFrontPage"] = value.ToString();
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// </summary>
        public bool UseHTTPS {
            get {
                return Convert.ToBoolean(Map["UseHTTPS"]);
            }
            set {
                Map["UseHTTPS"] = value.ToString();
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// </summary>
        public bool UseExternalLoginSite {
            get {
                return Convert.ToBoolean(Map["UseExternalLoginSite"]);
            }
            set {
                Map["UseExternalLoginSite"] = value.ToString();
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// </summary>
        public string ExternalLoginURL {
            get {
                return Map["ExternalLoginURL"];
            }
            set {
                Map["ExternalLoginURL"] = value.ToString();
            }
        }

//New from the MGL.DataLAyer.LoginConfig control

            /// <summary>
            /// The location of the T & C page.
            /// </summary>
            public string TermsAndConditions
            {
                get
                {
                    return Map["TermsAndConditions"];
                }
                set
                {
                    Map["TermsAndConditions"] = value;
                }
            }




            /// <summary>
            /// If true, the login checking allow guests into secure areas
            /// (think this is only going to be required for the demo but worth having just in case)
            /// </summary>
            public bool AllowGuestsIntoSecureAreas
            {
                get
                {
                    try
                    {
                        return Convert.ToBoolean(Map["AllowGuestsIntoSecureAreas"]);
                    }
                    catch (Exception)
                    {
                        return false;
                    }

                }
                set
                {
                    Map["AllowGuestsIntoSecureAreas"] = value.ToString();
                }
            }




            /// <summary>
            /// The default usertype when a user registers
            /// for the site
            /// </summary>
            public string DefaultRegistrationType
            {
                get
                {
                    return Map["DefaultRegistrationType"];
                }
                set
                {
                    Map["DefaultRegistrationType"] = value;
                }
            }

            /// <summary>
            /// Flag indicates if application should switch to using a secure DB
            /// after login.
            /// </summary>
            public bool UseSecureDBOnLogin
            {
                get
                {
                    return Convert.ToBoolean(Map["UseSecureDBOnLogin"]);
                }
                set
                {
                    Map["UseSecureDBOnLogin"] = value.ToString();
                }
            }

            /// <summary>
            /// Flag indicates if new users must be vetted by the affiliate
            /// before using the application.
            /// </summary>
            public bool RequireNewUserVetting
            {
                get
                {
                    return Convert.ToBoolean(Map["RequireNewUserVetting"]);
                }
                set
                {
                    Map["RequireNewUserVetting"] = value.ToString();
                }
            }


        #endregion

    }

}
