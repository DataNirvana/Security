using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using MGL.DomainModel;
using MGL.Data.DataUtilities;

namespace MGL.Security {
    public static class UserParseXML {


        //------------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static MGUser ParseUser(XmlDocument xmlDoc) {
            MGUser u = new MGUser();



            try {

                // get the last bit of MGL.GEDI.DomainModel.MGUser ....
                //DEOBFUSCATE????
                string typeOfUser = "MGUser";
                try {
                    string[] bits = typeof(MGUser).ToString().Split('.');
                    typeOfUser = bits[bits.Length - 1];
                } catch (Exception ex) {
                    Logger.LogError(5, "Error parsing the User XML: " + ex.ToString());
                }
                XmlNodeList users = xmlDoc.GetElementsByTagName(typeOfUser);
                foreach (XmlNode node in users) {

                    foreach (XmlNode child in node.ChildNodes) {
                        int tempInt = 0;
                        bool tempBool = false;
                        DateTime tempDate = DateTime.Now;

                        if (child.Name.Equals("ID", StringComparison.CurrentCultureIgnoreCase)) {
                            int.TryParse(child.ChildNodes[ 0 ].Value, out tempInt);
                            u.ID = tempInt;

                        } else if (child.Name.Equals("UserName", StringComparison.CurrentCultureIgnoreCase)) {
                            u.Username = SecureStringWrapper.Encrypt( child.ChildNodes[0].Value );

                        } else if (child.Name.Equals("IsNew", StringComparison.CurrentCultureIgnoreCase)) {
                            bool.TryParse(child.ChildNodes[0].Value, out tempBool);
                            u.IsNew = tempBool;

                        } else if (child.Name.Equals("Email", StringComparison.CurrentCultureIgnoreCase)) {
                            u.Email = SecureStringWrapper.Encrypt(child.ChildNodes[0].Value);

                        } else if (child.Name.Equals("LastIP", StringComparison.CurrentCultureIgnoreCase)) {
                            u.LastIP = child.ChildNodes[0].Value;

                        } else if (child.Name.Equals("LastBrowser", StringComparison.CurrentCultureIgnoreCase)) {
                            u.LastBrowser = child.ChildNodes[0].Value;

                        } else if (child.Name.Equals("TotalLogins", StringComparison.CurrentCultureIgnoreCase)) {
                            int.TryParse(child.ChildNodes[0].Value, out tempInt);
                            u.TotalLogins = tempInt;

                        } else if (child.Name.Equals("NumIncorrectLogins", StringComparison.CurrentCultureIgnoreCase)) {
                            int.TryParse(child.ChildNodes[0].Value, out tempInt);
                            u.NumIncorrectLogins = tempInt;

                        } else if (child.Name.Equals("LastLogin", StringComparison.CurrentCultureIgnoreCase)) {
                            DateTime.TryParse(child.ChildNodes[ 0 ].Value, out tempDate);
                            u.LastLogin = tempDate;

                        } else if (child.Name.Equals("StartDate", StringComparison.CurrentCultureIgnoreCase)) {
                            DateTime.TryParse(child.ChildNodes[0].Value, out tempDate);
                            u.StartDate = tempDate;

                        }


                    }

                }

            } catch (Exception ex) {
                Logger.LogError(5, "UserParseXML ParseUser:" + ex + "Error extracting the User from the xml");
            } finally {

            }


            return u;
        }



    }
}
