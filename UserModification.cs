using System;
using System.Data;
using System.Configuration;
using System.Collections.Generic;
using System.Collections;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;
using MGL.Data.DataUtilities;
using MGL.DomainModel;
using OfficeOpenXml;
using System.IO;
using System.Threading;
using MGL.Security.Email;
using System.Security;
using System.Text.RegularExpressions;
using DataNirvana.Database;


//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    enum Groups {
        One = 1,
        Two = 2,
        Four = 4,
        Eight = 8
    }



    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Summary description for UserModification
    /// </summary>
    public class UserModification : BaseSecurityOperations {

//        private static string thisClassName = "MGL.Security.UserModification";

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Note that the User Modification which may be called from other threads and is the ONLY case in which the password field length should not be checked
        ///     as it references the MGLApplicationSecuityInterface which is not accessible in other threads... (Excel export is conducted in a separate thread ...
        /// </summary>
        public UserModification(ConfigurationInfo configFile)
            : base(configFile, false) {
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     12-Oct-2015 - Updated to use SecureStrings ...
        /// </summary>
        public bool DoUserModification(int loggedInUserID, SecureString[] data, out string responseText, bool useMGLRatherThanMySQLPasswordEncryption, bool useHttps) {
            bool success = false;

            responseText = "";

            /*
             *  These are the columns in the User Spreadsheet:
             *  1. S.No
             *  2. First Name
             *  3. Last Name
             *  4. UserName
             *  5. Password
             *  6. Job Title / Role in GD
             *  7. Organisation Acronym
             *  8. Telephone Number
             *  9. Email Address
             *  10. Is User?
             *  11. Is Data Entry?
             *  12. Is Data Admin? / Professional User
             *  13. Is Global Data Admin? / Secure User
             *  14. Is User Admin ?
             *  15. Is Website Admin?
             *  16. Status
             *  17. Organisation ID
            */

            UserOperations uOps = null;
            GroupOperations gOps = null;
            GroupAdministration gAdmin = null;
            MGGroup group = null;
            MGUser u = null;

            bool isCaseSensitive = false;

            try {

                // 4-Dec-16 - this is causing this to fall over .... Get the OrgID by decrypting the input
                int orgID = 0;
                StringBuilder orgSB = SecureStringWrapper.Decrypt(data[16]);
                int.TryParse(orgSB.ToString(), out orgID);


                uOps = new UserOperations(lcf);
                uOps.CheckForPasswordChangeDateColumn();

                gOps = new GroupOperations(lcf);
                gAdmin = new GroupAdministration( lcf );

                if (data != null && data.Length >= 16) {

                    //_____ Check to see if this username exists already and whether or not the password should be mandatory ....
                    bool existsAlreadyUserName = data[3] != null && data[3].Length > 0 && UserNameAlreadyExists( data[3]);
                    bool existsAlreadyEmailAddress = data[ 8 ] != null && data[ 8 ].Length > 0 && EmailAlreadyExists(data[8]);
                    bool isDelete = false;

                    bool passwordIsMandatory = (existsAlreadyEmailAddress == false && existsAlreadyUserName == false)
                        || (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[15]), new StringBuilder("Password Reset"), isCaseSensitive) == true);

                    bool groupIDsOK = false;

                    //_____ Check that all mandatory fields have been filled (Note that the response text will automatically be reset by this method - if you want to only add to the responseText if there is an error
                    // then this will need to be setting a temporary variable.
                    bool mandatoryFieldsOK = CheckMandatoryFields(data, passwordIsMandatory, out responseText);


                    //______ Build the list of cross references ...
                    List<int> groupIDs = new List<int>();
                    {
                        StringBuilder yesSB = new StringBuilder("yes");

                        // 10. Is User?
                        if (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[9]), yesSB, isCaseSensitive) == true) {
                            //data[9] != null && SecureStringWrapper.AreEqual( data[9], SecureStringWrapper.Encrypt("yes"), false)) {
                            group = gOps.GetGroup("User");
                            if (group.ID > 0) {
                                groupIDs.Add(group.ID);
                            }
                        }

                        // 22-Jan-2015 - amended this to be DataENTRY!  Previously it was "DataAdmin"
                        // 11. Is Data Entry?
                        if (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[10]), yesSB, isCaseSensitive) == true) {
                            //data[10].Equals("yes", StringComparison.CurrentCultureIgnoreCase)) {
                            group = gOps.GetGroup("DataEntry");
                            if (group.ID > 0) {
                                groupIDs.Add(group.ID);
                            }
                        }

                        // 3-Dec-2016 - Reordered these to make more sense in the spreadsheet....

                        // 12. Is Data Admin / Professional User?
                        if (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[11]), yesSB, isCaseSensitive) == true) {
                            //data[14].Equals("yes", StringComparison.CurrentCultureIgnoreCase)) {
                            group = gOps.GetGroup("ProfessionalUser");
                            if (group.ID > 0) {
                                groupIDs.Add(group.ID);
                            }
                        }

                        // 14. Is Global Data Administrator / Secure User?
                        if (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[12]), yesSB, isCaseSensitive) == true) {
                            //data[13].Equals("yes", StringComparison.CurrentCultureIgnoreCase)) {
                            group = gOps.GetGroup("SecureUser");
                            if (group.ID > 0) {
                                groupIDs.Add(group.ID);
                            }
                        }

                        // 13. Is User Admin?
                        if (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[13]), yesSB, isCaseSensitive) == true) {
                            //data[12].Equals("yes", StringComparison.CurrentCultureIgnoreCase)) {
                            group = gOps.GetGroup("UserAdmin");
                            if (group.ID > 0) {
                                groupIDs.Add(group.ID);
                            }
                        }

                        // 15. Is Website Admin?
                        if (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[14]), yesSB, isCaseSensitive) == true) {
                            //data[11].Equals("yes", StringComparison.CurrentCultureIgnoreCase)) {
                            group = gOps.GetGroup("Admin");
                            if (group.ID > 0) {
                                groupIDs.Add(group.ID);
                            }
                        }


                        // each user must belong to at least one group, so flag this as an error if groupIDs.Count == 0
                        if (groupIDs.Count > 0) {
                            groupIDsOK = true;
                        } else {
                            // only update the response text if it is not already set - the Mandatory fields are a more serious error that should make more sense to the User ...
                            responseText = (responseText.Length > 0) ? responseText :
                                "Error - This user does not belong to any groups.  Each User should belong to at least ONE group.  Please check the data you have provided and try again.";
                            success = false;
                        }

                    }


                    //_____ Attempt the Insert or Update ...
                    if (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[15]), new StringBuilder("Delete"), isCaseSensitive) == true) {
                    //if (data[15] != null && SecureStringWrapper.AreEqual(data[15], SecureStringWrapper.Encrypt("Delete"), false)) {
                        //data[15].Equals("Delete", StringComparison.CurrentCultureIgnoreCase)) {                                                     // This is an DELETE

                        isDelete = true;

                        u = uOps.GetUserByUsername(data[3]);

                        // 13-Oct-2015 - Oooops - lets stop the currently logged in user from deleting themselves unintentionally!!
                        if (u != null && u.ID > 0) {

                            if (u.ID == loggedInUserID) {
                                responseText = "Error - You are trying to delete yourself!  This is not allowed - if you want to remove your account, request another administrator to do this for you.";
                            } else {
                                // lets get it ON
                                success = DeleteUser(u.ID);
                                success = success & DeleteUsersGroupXrefs(u.ID);

                                if (success) {
                                    responseText = "Deleted";
                                } else {
                                    if (existsAlreadyUserName == false) {
                                        responseText = "Error - Could not delete this user as they are not listed in this system - please check the data you have provided and try again.";
                                    } else {
                                        responseText = "Error - Could not delete this user - please check the data you have provided and try again.";
                                    }
                                }
                            }
                        } else {
                            responseText = "Error - Could not find the user to delete - please check the data you have provided and try again.";
                        }


                    } else if (existsAlreadyEmailAddress == false && existsAlreadyUserName == false) {                                  // This is an INSERT

                        // Only commit the user if the groupIDs and the Mandatory fields are ok ...
                        if (groupIDsOK && mandatoryFieldsOK == true) {

                            success = InsertUser(data[1], data[2], data[3], data[8], data[4], data[5], data[6], orgID, data[7], tnUsers, useMGLRatherThanMySQLPasswordEncryption);
                            u = uOps.GetUserByUsername(data[3]);

                            if (success) {
                                responseText = "Added";
                            } else {
                                responseText = "Error - Insert of new user failed - please check the data you have provided and try again.";
                            }
                        }

                    } else if ((existsAlreadyEmailAddress == true && existsAlreadyUserName == true)
                        || (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[15]), new StringBuilder("Email Change"), isCaseSensitive) == true)) {
//                        || (data[15] != null && SecureStringWrapper.AreEqual(data[15], SecureStringWrapper.Encrypt("Email Change"), false))) {
                        //data[15].Equals("Email Change", StringComparison.CurrentCultureIgnoreCase))) {                                            // This is an UPDATE

                        // Only commit the user if the groupIDs and the Mandatory fields are ok ...
                            if (groupIDsOK && mandatoryFieldsOK == true) {

                                u = uOps.GetUserByUsername(data[3]);

                                //_____ 3-Feb-2015 check for changes - and flag an error if there are none!!!  Note that this is case sensitive as these case changes might be useful corrections!
                                if (
                                    SecureStringWrapper.AreEqual( u.FirstName, data[1], true)
                                    && SecureStringWrapper.AreEqual( u.LastName, data[2], true)
                                    && SecureStringWrapper.AreEqual( u.Username, data[3], true)
                                    && SecureStringWrapper.AreEqual( u.Email, data[8], true)
                                    && SecureStringWrapper.AreEqual( u.JobTitle, data[5], true)
                                    && SecureStringWrapper.AreEqual( u.Organisation, data[6], true)
                                    && SecureStringWrapper.AreEqual( u.Telephone, data[7], true)
                                    ){

                                    // warn, but allow the processing to proceed!
                                    success = true;
                                    responseText = "Warning - No information has changed!  At least one of firstname, lastname, username, email address, job title, organisation, telephone or admin groups should be updated.";

                                } else {

                                    // lets see where the changes are occurring
                                    //bool test1 = SecureStringWrapper.AreEqual( u.FirstName, data[1], true);
                                    //bool test2 = SecureStringWrapper.AreEqual( u.LastName, data[2], true);
                                    //bool test3 = SecureStringWrapper.AreEqual( u.Username, data[3], true);
                                    //bool test4 = SecureStringWrapper.AreEqual( u.Email, data[8], true);
                                    //bool test5 = SecureStringWrapper.AreEqual( u.JobTitle, data[5], true);
                                    //bool test6 = SecureStringWrapper.AreEqual( u.Organisation, data[6], true);
                                    //bool test7 = SecureStringWrapper.AreEqual( u.Telephone, data[7], true);

                                    // 13-Oct-2015 - now verify that the email address is well formed ...
                                    StringBuilder emailAddress = SecureStringWrapper.Decrypt(data[8]);
                                    if (Regex.IsMatch(emailAddress.ToString(), "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$") == false) {
                                        responseText = "Error - The Email address provided is not well formed - please check the address you have provided and try again.";

                                    } else {

                                        success = UpdateUserDetails(u.ID, data[1], data[2], data[3], data[8], data[5], data[6], orgID, data[7]);
                                        u = uOps.GetUserByUsername(data[3]); // extract the information again, so that it is FRESH!

                                        if (success) {
                                            responseText = "Updated (excluding password)";
                                        } else {
                                            responseText = "Error - Update of user details failed - please check the data you have provided and try again.";
                                        }
                                    }
                                }
                            }

                    } else if (existsAlreadyEmailAddress == true) {                                                                                     // This is an ERROR - duplicate email address

                        u = uOps.GetUserByEmail(data[8]);
                        responseText = "Error - This email address exists already for UserName " + SecureStringWrapper.Decrypt( u.Username ) + ".";

                    } else if (existsAlreadyUserName == true) {                                                                                         // As this is not an email change, then this is also an ERROR

                        u = uOps.GetUserByUsername(data[3]);
                        responseText = "Error - This username exists already and the email in the database ("
                            + SecureStringWrapper.Decrypt( u.Email )
                            + ") does not match the one given in the spreadsheet.  If you still want to change the email address and go ahead with the update, then write 'Email Change' in the Status column and resubmit this User information ";

                    }

                    //_____ Only update the password if this is a new user ... as users also have the ability to change their own passwords?????
                    // Or if the specific keyword Password Reset is given ....
                    bool isPasswordReset = (MGLEncryption.AreEqual(SecureStringWrapper.Decrypt(data[15]), new StringBuilder("Password Reset"), isCaseSensitive) == true);
                        //(data[15] != null && SecureStringWrapper.AreEqual(data[15], SecureStringWrapper.Encrypt("Password Reset"), false));
                        //data[15].Equals("Password Reset", StringComparison.CurrentCultureIgnoreCase));

                    if (responseText.Equals("Added", StringComparison.CurrentCultureIgnoreCase) || isPasswordReset == true ) {

                        // 4-Jan-2015 - If this is a passwordReset, the user will likely still be null, so lets catch that issue!
                        if (u == null) {
                            u = uOps.GetUserByUsername(data[3]);
                        }

                        // 4-Jan-2015 - And if the issue persists, lets flag it as a new error ...
                        if (u == null || u.ID == 0) {
                            success = false;
                            Logger.LogError(114, "User has been added ('"+responseText+"') or a password reset has been requested ("
                                +isPasswordReset+") but cannot extract the user from the database using the userName: "+data[3]+".  Bad data in spreadsheet?");
                        } else {
                            success = UpdateUserPassword(u.ID, data[4], useMGLRatherThanMySQLPasswordEncryption);
                            if (success == true) {
                                DateTime pWordChangeTimeStamp = DateTime.Now;

                                UpdatePasswordChangeDate(u.ID, pWordChangeTimeStamp);

                                // 13-Jul-2015 - lets email the user to confirm that their password has changed!
                                if (isPasswordReset == true) {
                                    PasswordChangedEmailUser(u, pWordChangeTimeStamp, useHttps);
                                } else {
                                    // send a nice helpful and friendly welcome email ...
                                    WelcomeEmailUser(u, pWordChangeTimeStamp, useHttps);
                                }
                            }
                            success = success & UnlockUser(u.ID);
                        }

                        if (success) {
                            // 9-Jun-2015 - always update the response text, but ONLY if this is a password reset ....
                            if (isPasswordReset == true) {
                                responseText = "Updated";
                            }
                        } else {
                            responseText = "Error - Could not update the users password.  Please check the information you have provided and try again.";
                        }
                    }


                    //______ Now update the cross references ...
                    if (success == true && isDelete == false && groupIDsOK == true) {

                        // 9-Jun-2015 - We don't want to make changes unneccisarily, so this means we need to check that the group ID array has changed
                        // Then we only want to update the response text, if this is the only change ...
                        // 9-Jun-2015 - check for changes in the group arrays - which means that we first need to extract the group IDs ... and then use the Linq.sequenceEqual to check if the lists are equal...
                        if (u != null) {
                            u.Groups = uOps.GetUserGroupsIDs(u.ID);
                        }
                        bool areEqual = false;
                        if (u.Groups != null && u.Groups.Count == groupIDs.Count) {
                            u.Groups.Sort();
                            groupIDs.Sort();
                            areEqual = u.Groups.SequenceEqual(groupIDs);
                        }

                        // only try to make a change if there is a difference in the groups ....
                        if (areEqual == false) {
                            // The unassign does not seem to show that data is removed ...
                            // 5-Feb-2015 - Now while UnassignAllGroupsFromUser has a boolean response it is not very helpful to us as it returns false even if the process has run successfully but deleted no records ....
                            //.. which may not of existed in the first place - therefore - lets get rid!
                            gAdmin.UnassignAllGroupsFromUser(u.ID, false);
                            success = success & gAdmin.AssignUserToGroups(u.ID, groupIDs, false);

                            if (success == false) {
                                responseText = "Error - Could not update the Groups for this user.  Please check the data you have provided and try again.";

                            } else if (success == true && (responseText == "" || responseText.StartsWith("Warning", StringComparison.CurrentCultureIgnoreCase))) {
                                // 2-Jun-2015 - if just the user roles have changed, there will be warning text from the above that nothing has changed, so we want to overwrite this with an "Updated user roles" text
                                responseText = "Updated user role(s)";
                            }
                        }
                    }
                }


            } catch (Exception ex) {

                Logger.LogError(8, "Error modifying the user information: " + ex);
                responseText = "Error - Fatal error processing this users data.  Please check the data you have provided and try again.";

            } finally {

                if ( uOps != null ) {
                    uOps.Finish();
                }

                if ( gOps != null ) {
                    gOps.Finish();
                }


            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        private bool CheckMandatoryFields(SecureString[] data, bool passwordIsMandatory, out string responseText) {
            bool success = false;
            responseText = "";

            string temp = "";

            /*
             *  These are the columns in the User Spreadsheet:
             *  1. S.No
             *  2. First Name
             *  3. Last Name
             *  4. UserName
             *  5. Password
             *  6. Job Title / Role in GD
             *  7. Organisation
             *  8. Telephone Number
             *  9. Email Address
            *  10. Is User?
             *  11. Is Data Entry?
             *  12. Is Data Admin? / Professional User
             *  13. Is Global Data Admin? / Secure User
             *  14. Is User Admin ?
             *  15. Is Website Admin?
              *  16. Status
              *  17. Organisation ID
            */

            if ((data[1] == null || data[1].Length == 0)) {
                temp = temp + ((temp.Length > 0) ? ", " : "") + "Firstname";
            }

            if ((data[2] == null || data[2].Length == 0)) {
                temp = temp + ((temp.Length > 0) ? ", " : "") + "Lastname";
            }

            if ((data[3] == null || data[3].Length == 0)) {
                temp = temp + ((temp.Length > 0) ? ", " : "") + "Username";
            }

            if (passwordIsMandatory && (data[4] == null || data[4].Length == 0)) {
                temp = temp + ((temp.Length > 0) ? ", " : "") + "Password";
            }

            if ((data[6] == null || data[6].Length == 0)) {
                temp = temp + ((temp.Length > 0) ? ", " : "") + "Organisation";
            }

            if ((data[8] == null || data[8].Length == 0)) {
                temp = temp + ((temp.Length > 0) ? ", " : "") + "Email Address";
            }

            if (temp.Length > 0) {
                responseText = "ERROR - One or more mandatory fields are missing as follows: " + temp + ".  Please add this information and try again";
            } else {
                success = true;
            }

            return success;
        }



        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///
        /// </summary>
        public bool ExportAllUsersExcel(out byte[] fileContent, string physicalPathToApplicationRoot, string seshID) {
            bool success = false;

            fileContent = null;
            UserOperations uOps = null;
            GroupOperations gOps = null;
            ExcelPackage excelPack = null;

            try {

                ExportFilesInfo.UpdateProgress(seshID, 5); //=============

                uOps = new UserOperations(lcf);
                gOps = new GroupOperations(lcf);

                List<MGUser> users = uOps.GetAllUsers();

                if (users == null || users.Count == 0) {
                    Logger.LogError(9, "Could not extract the list of Users from the Database!  Something very weird going on");
                } else {

                    //_____ Build the excel here, based on the template, which makes it VERY easy to introduce column widths and formulas etc ...
                    FileInfo template = new FileInfo(physicalPathToApplicationRoot + "App_Data/UserExportTemplate.xlsx");
                    excelPack = new ExcelPackage(template, true);

                    ExcelWorksheet ws = excelPack.Workbook.Worksheets["UserList"];


                    MGGroup groupUser = gOps.GetGroup("User");
                    // 22-Jan-2015 - amended this to be DataENTRY!  Previously it was "DataAdmin"
                    // UPDATE `idpgrievances_datanirvana`.`security_groups` SET `GroupName`='DataEntry' WHERE `ID`='3';
                    MGGroup groupDataEntry = gOps.GetGroup("DataEntry");
                    // Data Administrator or Professional User
                    MGGroup groupProfessionalUser = gOps.GetGroup("ProfessionalUser");
                    // Global Data Administrator or Secure User
                    MGGroup groupSecureUser = gOps.GetGroup("SecureUser");
                    MGGroup groupUserAdmin = gOps.GetGroup("UserAdmin");
                    MGGroup groupAdmin = gOps.GetGroup("Admin");

                    /*
                     *  These are the columns in the User Spreadsheet:
                     *  1. S.No
                     *  2. First Name
                     *  3. Last Name
                     *  4. UserName
                     *  5. Password
                     *  6. Job Title / Role in GD
                     *  7. Organisation Acronym
                     *  8. Telephone Number
                     *  9. Email Address

                     *  10. Is User?
                    *  11. Is Data Entry?
                    *  12. Is Data Admin? / Professional User
                    *  13. Is Global Data Admin? / Secure User
                    *  14. Is User Admin ?
                    *  15. Is Website Admin?
                    *  16. Status

                    lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll
                     *  11. Is Data Admin?
                     *  12. Is Website Admin?
                     *  13. Is User Admin?
                     *  14. Is Secure User?
                     *  15. Is Professional User?
                     *  16. Status
                    */

                    ExportFilesInfo.UpdateProgress(seshID, 10); //=============

                    // OK now we have the meaty bit and we have 80% of the processing stuff, so lets work out how much one row is and then update every ten ...
                    double rowIncrement = 80.0 / (double)users.Count;


                    //_____ Restructure the User Information
                    int rowCount = 2;
                    foreach (MGUser u in users) {

                        // log every ten records ...
                        if (rowCount % 10 == 0) { ExportFilesInfo.UpdateProgress(seshID, (int)Math.Floor(10.0 + ((double)rowCount * rowIncrement))); } //=============

                        //_____ Extract the list of groups that this User is in ....
                        List<int> groups = uOps.GetUserGroupsIDs(u.ID);

                        //_____ Go through and append all the data to each cell in the row ....
                        ws.Cells["A"+rowCount].Value = u.ID;
                        ws.Cells["B" + rowCount].Value = SecureStringWrapper.Decrypt( u.FirstName ).ToString();
                        ws.Cells["C" + rowCount].Value = SecureStringWrapper.Decrypt( u.LastName ).ToString();
                        ws.Cells["D" + rowCount].Value = SecureStringWrapper.Decrypt( u.Username ).ToString();
                        // Note that this assumes MGLEncryption is used for the password, rather than the MySQL encryption ...
                        ws.Cells["E" + rowCount].Value = ""; // 5-July-2015 - No longer exporting the Passwords for security reasons ... MGLEncryption.DecryptPassword( u.Password );
                        ws.Cells["F" + rowCount].Value = SecureStringWrapper.Decrypt( u.JobTitle ).ToString();
                        ws.Cells["G" + rowCount].Value = SecureStringWrapper.Decrypt( u.Organisation ).ToString();
                        ws.Cells["H" + rowCount].Value = SecureStringWrapper.Decrypt( u.Telephone ).ToString();
                        ws.Cells["I" + rowCount].Value = SecureStringWrapper.Decrypt(u.Email).ToString();
                        ws.Cells["J" + rowCount].Value = (groupUser != null && groups.Contains( groupUser.ID )) ? "Yes" : "";
                        ws.Cells["K" + rowCount].Value = (groupDataEntry != null && groups.Contains(groupDataEntry.ID)) ? "Yes" : "";
                        // Data Administrator
                        ws.Cells["L" + rowCount].Value = (groupProfessionalUser != null && groups.Contains(groupProfessionalUser.ID)) ? "Yes" : "";
                        // Global Data Administrator
                        ws.Cells["M" + rowCount].Value = (groupSecureUser != null && groups.Contains(groupSecureUser.ID)) ? "Yes" : "";
                        ws.Cells["N" + rowCount].Value = (groupUserAdmin != null && groups.Contains(groupUserAdmin.ID)) ? "Yes" : "";
                        ws.Cells["O" + rowCount].Value = (groupAdmin != null && groups.Contains(groupAdmin.ID)) ? "Yes" : "";
                        ws.Cells["P" + rowCount].Value = "";

                        rowCount++;
                    }

                }

                ExportFilesInfo.UpdateProgress(seshID, 90); //=============

                //_____ Now Setup the Summary Page of the Spreadsheet ... Updating the modification date ...
                ExcelWorksheet wsSummary = excelPack.Workbook.Worksheets["Summary"];
                wsSummary.Cells["C3"].Formula = "=COUNTA(UserList!I:I)-1";
                wsSummary.Cells["C4"].Value = DateTime.Now;
                wsSummary.Cells["C4"].Style.Numberformat.Format = "dd-MMM-yy";
                wsSummary.Cells["C5"].Formula = "=COUNTIF(UserList!P:P, \"Added\" )";
                wsSummary.Cells["C6"].Formula = "=COUNTIF(UserList!P:P, \"Modified\" )";
                wsSummary.Cells["C7"].Formula = "=COUNTIF(UserList!P:P, \"Deleted\" )";
                wsSummary.Cells["C8"].Formula = "=COUNTIF(UserList!P:P, \"Error*\" )";


                //_____ Finally - spit out the excel file to the output byte array stream ....
                fileContent = excelPack.GetAsByteArray();

                if (fileContent.Length > 0) {
                    success = true;
                }

                ExportFilesInfo.UpdateProgress(seshID, 100); //=============

            } catch (System.Threading.ThreadAbortException exThreadAbortException) {

                // Do absolutely fuck all - this is a non exception!

            } catch (Exception ex) {

                Logger.LogError(9, "Error modifying the user information: " + ex);

            } finally {

                if (uOps != null) {
                    uOps.Finish();
                }

                if (gOps != null) {
                    gOps.Finish();
                }

                // Tidy up ...
                if (excelPack != null) {
                    excelPack.Dispose();
                }
            }


            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     The default Change Password method called from Change Password.aspx as well as the UserAdmin code ...
        /// </summary>
        public bool UpdatePassword(int userID, SecureString userName, SecureString currentPassword, SecureString newPassword, out string errorMessage,
            bool useMGLRatherThanMySQLPasswordEncryption, string mglSessionID, bool useHttps) {

            bool success = false;
            errorMessage = "";

            UserOperations userOps = new UserOperations(lcf);
            MGUser u = null;

            bool isAHuman = LoggerDB.IsHuman(lcf, mglSessionID, "PasswordChange", 1);

            if (isAHuman == false) {
                errorMessage = Authorisation.GeneralError;
            } else {

                //_____ Test 0 - Check that the new and the old passwords are different
                if (currentPassword == null || currentPassword.Length == 0) {
                    errorMessage = "The current password is invalid.  Please try entering your correct password again.";
                } else if (newPassword == null || newPassword.Length == 0) {
                    errorMessage = "The new password is invalid.  Please try entering a different secure password.";
                } else if (SecureStringWrapper.AreEqual( currentPassword, newPassword, false)) {
                    errorMessage = "The current and new passwords are the same which is not allowed.  Please change the new password and try again.";
                } else if (newPassword.Length < 8 || newPassword.Length > 200) {
                    errorMessage = "The new password is not strong enough.  It should always be a minimum of 8 characters including at least one each of alpha, numeric and funny characters.  Please think up a better password and try again.";
                } else {
                    success = true;
                }


                //_____ Test 1 - Check that the UserID and UserName match ...
                if (success == true) {
                    success = false; // reset for test 2 ...

                    List<MGUser> users = userOps.GetAllUsers();

                    if (users != null && users.Count > 0) {

                        foreach (MGUser tempU in users) {

                            if (SecureStringWrapper.AreEqual(tempU.Username, userName, false )) {
                                //tempU.Username.Equals(userName, StringComparison.CurrentCultureIgnoreCase)) {
                                if (tempU.ID == userID) {
                                    u = tempU;
                                    success = true;
                                    break;

                                }
                            }

                        }

                    } else {
                        success = false;
                    }

                    if (success == false) {
                        errorMessage = "User ID and username combination do not match.  Please try logging out and in again.";
                    }
                }


                //_____ Test 2 - check that the username and current password match
                if (success == true) {
                    success = success & userOps.UserLoginDetailsCorrect(userName, currentPassword);

                    if (success == false) {
                        errorMessage = "Username and password combination do not match.  Please try entering your correct password again.";
                    }
                }


                //_____ Do It NOW - Update the users password and the date and time on which it was changed ...
                if (success == true) {
                    success = UpdateUserPassword(userID, newPassword, useMGLRatherThanMySQLPasswordEncryption);

                    DateTime pWordChangeTimeStamp = DateTime.Now;

                    UpdatePasswordChangeDate(userID, pWordChangeTimeStamp);

                    // 13-Jul-2015 - lets email the user to confirm that their password has changed!
                    PasswordChangedEmailUser(u, pWordChangeTimeStamp, useHttps);

                    // finally login again with the correct password .... This will also update the session variable storing all of the user information ...
                    success = success && Authorisation.DoLogin(userName, newPassword);

                    if (success == false) {
                        errorMessage = "Could not update the password successfully.  Please try again.";
                    }

                }
            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool PasswordRequestReset(string mglSessionID, SecureString userNameOrEmail, out string errorMessage,
            bool useMGLRatherThanMySQLPasswordEncryption, bool useHttps) {

            bool success = false;
            errorMessage = "";

            //_____Captcha Test alternative - check that this page was requested between 15 seconds and 5 minutes ago by this user (session ID)
            // It is important that a - this page WAS requested, as this indicates that the user is likely to be a human requesting the page, then entering some info
            // then responding ...
            //MGLSessionInterface.Instance().SessionID
            bool isAHuman = LoggerDB.IsHuman(lcf, mglSessionID, "PasswordRequestReset", 2);

            if (isAHuman == false) {
                errorMessage = Authorisation.GeneralError;
            } else {

                UserOperations userOps = new UserOperations(lcf);

                //_____ Get the user info
                List<MGUser> users = userOps.GetAllUsers();

                MGUser uselessUser = null;

                if (users != null && users.Count > 0) {

                    foreach (MGUser u in users) {

                        if (SecureStringWrapper.AreEqual( u.Username, userNameOrEmail, false ) == true
                            || SecureStringWrapper.AreEqual(u.Email, userNameOrEmail, false) == true) {
                           //|| u.Email.Equals(userNameOrEmail, StringComparison.CurrentCultureIgnoreCase)) {

                            uselessUser = u;
                            success = true;
                            break;

                        }
                    }
                }

                if (success == false) {
                    // slow down potential hackers searching for invalid email addresses or user names ...
                    Thread.Sleep(new Random().Next(100));
                    errorMessage = "Could not find the specified user. Please check your spelling and try again.";
                } else {

                    // Create a password reset token based on a random salt string and hash it and then encrypt it ...
                    // GUID is too well known and COULD be guessed at?
                    //string tokenStr = MGLEncryption.GetSalt(13); // System.Guid.NewGuid().ToString();
                    StringBuilder token = MGLEncryption.GetSalt(13);
                    // 17-Jul-15 - Removed this as it does not really matter if the token is unbreakable - another user just needs to be able to use the token to get in
                    // if e.g. the User's email address has been cracked.
                    // Also double encryption meant that the token was often over 700 characters which is simply too long to be relevant!
                    //string hashedToken = MGLPasswordHash.EncryptPassword(token);
                    //string encryptedToken = MGLEncryption.Encrypt( hashedToken );
                    StringBuilder encryptedToken = MGLEncryption.Encrypt(token);

                    StringBuilder htmlToken = MGLEncryption.HTMLifyString(encryptedToken);

                    string httpPrefix = (useHttps == true) ? "https" : "http";

                    // 25-Nov-2015 - localise the dates
                    string prettyLocalDate = "";
                    success = LocaliseTime.Localise(lcf, DateTime.Now, 3, uselessUser.ID, out prettyLocalDate);

                    // Send an email
                    string messageBody =
                        "<p style='font-family: Trebuchet MS;'>"
                            + "Hi " + SecureStringWrapper.Decrypt( uselessUser.FirstName ) + ", "
                            + "<br /><br />"
                            + "You requested that your password be reset on <b>" + prettyLocalDate
                            //DateTimeInformation.PrettyDateTimeFormat(DateTime.Now, this.timezoneOffset)
                            + "</b>.  If this was not you, please contact your web team <i>immediately</i> (by replying to this email)."
                            + " Your username for <b>" + Authorisation.ApplicationName + "</b> is given below: "

                            + "<br /><br />"
                            + "Username: <b>" + SecureStringWrapper.Decrypt( uselessUser.Username ) + "</b>"

                            + "<br /><br />"
                            + "To reset your password, click on the following link, which will redirect you to the password reset page on the website: "
                            + "<b><a href='" + httpPrefix + "://" + Authorisation.ApplicationURL + "/Code/Security/PasswordReset.aspx?Token=" +
                            htmlToken + "'>" + Authorisation.ApplicationURL + "</a></b>"

                            + "<br /><br />"
                            + "Cheers, <br />The " + Authorisation.ApplicationName + " Support Team"

                            + "<br /><br /></p>"
                            ;


                    // And send the email ...
                    success = MGLSecureEmailer.SendEmail(
                        SecureStringWrapper.Decrypt( uselessUser.Email ),
                        SecureStringWrapper.Decrypt( uselessUser.FirstName ),
                        Authorisation.ApplicationName + " - Password reset request", messageBody,
                        "", null, null, null, null, 0, MGLSecureEmailer.EnableSSL);


                    //_____ Lastly, lets add this user to the list of users that have requested password resets ...
                    PasswordResetWidget prw = new PasswordResetWidget(uselessUser.ID, token, DateTime.Now);
                    PasswordReset.SetWidget(prw);

                    if (success == false) {
                        errorMessage = "Could not set the password reset request successfully.  Please try again.";
                    }

                }
            }

            return success;
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     The Reset Password doing method called from ResetPassword.aspx
        ///     2-Dec-2015 - Pass out the user name so that we can log it in external apps.
        /// </summary>
        public bool ResetPassword(
            string mglSessionID, StringBuilder resetToken, SecureString newPassword,
            out string errorMessage, bool useMGLRatherThanMySQLPasswordEncryption, bool useHttps, out SecureString uUName) {

            bool success = false;
            errorMessage = "";

            MGUser u = null;
            PasswordResetWidget prw = null;
            uUName = null;

            if (resetToken == null || resetToken.Length == 0) {
                // 30-Oct-2015 - Catch no token to decryt ... probably as the user has modified the URL themselves?.
                errorMessage = "The reset link is corrupted. Please request another one below.";
                Logger.LogError(8, "PasswordReset postback - No reset link was provided - probably as the user has modified the URL themselves");

            } else {

                UserOperations userOps = new UserOperations(lcf);

                // get the userID from the application level LK table ...
                StringBuilder rToken = MGLEncryption.DeHTMLifyString(resetToken);
                StringBuilder decryptedToken = MGLEncryption.Decrypt(rToken);
                prw = PasswordReset.GetWidget(decryptedToken);


                if (prw == null || prw.UserID == 0) {
                    // 30-Oct-2015 - Catch the prw being null here and flag it as an error ... it has probably occured as the reset token has expired or has already been used.
                    errorMessage = "This reset request has expired or is not valid.  Please request another one below.";
                } else {

                    u = userOps.GetUser(prw.UserID);
                    uUName = u.Username;

                    //_____Captcha Test alternative - check that this page was requested between 15 seconds and 5 minutes ago by this user (session ID)
                    // It is important that a - this page WAS requested, as this indicates that the user is likely to be a human requesting the page, then entering some info
                    // then responding ...
                    //MGLSessionInterface.Instance().SessionID
                    bool isAHuman = LoggerDB.IsHuman(lcf, mglSessionID, "PasswordReset", 1);

                    if (isAHuman == false) {
                        errorMessage = Authorisation.GeneralError;
                    } else {

                        //_____ Test 0 - Check that the new and the old passwords are different
                        if (resetToken == null || resetToken.Length == 0) {
                            errorMessage = "The reset link is no longer valid.  Please request another one.";
                        } else if (newPassword == null || newPassword.Length == 0) {
                            errorMessage = "The new password is invalid.  Please try entering a different secure password.";
                        } else if (
                            MGLPasswordHash.Compare(
                                SecureStringWrapper.Decrypt(newPassword),
                                SecureStringWrapper.Decrypt(u.Password)) == true) {

                            errorMessage = "Please change the new password as it is the same as your current password!";
                        } else if (newPassword.Length < 8 || newPassword.Length > 200) {
                            // This error message should never be reached now we are using the password strengthify on the client side, but its still good to check.
                            errorMessage = "The new password must be at least 8 characters and include at least one alpha, numeric and other character.";
                        } else {
                            success = true;
                        }
                    }
                }
            }

            //_____ Do It NOW - Update the users password and the date and time on which it was changed ...
            if (success == true) {

                success = UpdateUserPassword(prw.UserID, newPassword, useMGLRatherThanMySQLPasswordEncryption);
                DateTime pWordChangeTimeStamp = DateTime.Now;
                UpdatePasswordChangeDate(prw.UserID, pWordChangeTimeStamp);

                // 22-Jul-2015 - Unlock the user if this is required ... and ONLY if everything else has worked ...
                success = success & UnlockUser(prw.UserID);

                // 13-Jul-2015 - lets email the user to confirm that their password has changed!
                PasswordChangedEmailUser(u, pWordChangeTimeStamp, useHttps);

                // remove the temporary token
                PasswordReset.RemoveWidget(prw);

                // finally login again with the correct password .... This will also update the session variable storing all of the user information ...
                success = success && Authorisation.DoLogin(u.Username, newPassword);

                if (success == false) {
                    errorMessage = "Could not update the password successfully.  Please try again.";
                }

            }


            return success;
        }



        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     One time method to convert all passwords in the database from the oldschool MGL style to the new more secure version.
        /// </summary>
        public bool ConvertAllPasswords() {

            bool success = true;    // innocent until proven guilty ...

            UserOperations userOps = new UserOperations(lcf);

            // iterate through all the user information and convert the password!
            foreach (int userID in MGLApplicationSecurityInterface.Instance().Users.Keys) {

                // Get the User info from the db
                MGUser u = userOps.GetUser(userID);

                if (u != null) {
                    if (u.Password != null && u.Password.ToString().Contains(":") == false) {

                        string decryptedPassword = MGLEncryptionOLD.DecryptPassword(SecureStringWrapper.Decrypt( u.Password).ToString());

                        StringBuilder encryptedPassword = MGLPasswordHash.EncryptPassword(new StringBuilder(decryptedPassword));

                        // UPDATE USER PASSWORD does the encryption for us!!!!!!! So we need to pass the decrypted version
                        success = success & UpdateUserPassword(u.ID, SecureStringWrapper.Encrypt( decryptedPassword ), true);

                    }
                }
            }

            return success;
        }


    }
}