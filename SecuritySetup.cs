using System;
using System.Collections.Generic;
using System.Text;
using MGL.DomainModel;
using MGL.Data.DataUtilities;

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {


    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    public static class SecuritySetup {

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        internal static bool RequireSecurity = true;

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
//        public static void Configure(bool requireSecurity, string applicationName, ConfigurationInfo lcf, LoginConfig loginConfig) {
        public static void Configure(bool requireSecurity, string applicationName, string applicationURL, ConfigurationInfo lcf) {
            // no need to setup if security is not required
            if (requireSecurity) {
//                Authorisation.Authorisation.SetupSecurity(applicationName, lcf, loginConfig );
                Authorisation.SetupSecurity(applicationName, applicationURL, lcf);
            }
            RequireSecurity = requireSecurity;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static List<MGUser> AllUsers() {
            // Get all the Users
            List<MGUser> allUsers = null;
            UserOperations userOps = null;

            try
            {
                userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
                allUsers = userOps.GetAllUsers();
            }
            catch (Exception ex)
            {
                Logger.LogError(9, "Problem getting all users at " + ex);
                return null;
            }
            finally
            {
                if (userOps != null)
                    userOps.Finish();
            }

            return allUsers;

        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static List<MGGroup> AllGroups() {
            // Get all the Groups
            List<MGGroup> allGroups = null;

            GroupOperations groupOps = null;

            try
            {
                groupOps = new GroupOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
                allGroups = groupOps.GetAllGroups();
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Problem getting all groups at " + ex);
                return null;
            }
            finally
            {
                if (groupOps != null)
                    groupOps.Finish();
            }

            return allGroups;
        }

    }
}
