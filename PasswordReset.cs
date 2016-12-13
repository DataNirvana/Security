using System;
using System.Collections.Generic;
using System.Text;
using System.ComponentModel;
using MGL.Data.DataUtilities;
using System.Threading;

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    ///     List of users currently resetting their passwords ....
    /// </summary>
    internal class PasswordReset {


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        private static List<PasswordResetWidget> Widgets = new List<PasswordResetWidget>();

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///      Set Widget - add or update ...
        /// </summary>
        public static void SetWidget(PasswordResetWidget paw) {

            RemoveWidget(paw);

            lock (PasswordReset.Widgets) {
                Widgets.Add(paw);
            }
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Get Widget
        /// </summary>
        public static PasswordResetWidget GetWidget(int userID) {
            PasswordResetWidget paw = null;

            foreach (PasswordResetWidget tempPAW in Widgets) {
                if (tempPAW.UserID == userID) {
                    paw = tempPAW;
                    break;
                }
            }

            return paw;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Get Widget
        /// </summary>
        public static PasswordResetWidget GetWidget(StringBuilder guid) {
            PasswordResetWidget paw = null;

            if (guid != null && guid.Length > 0) {
                foreach (PasswordResetWidget tempPAW in Widgets) {
                    // 17-Jul-15 - the MGLPasswordHash is overkill here, lets just use one level of encryption...
                    //if (MGLPasswordHash.Compare(  tempPAW.Guid, hashedGUID ) == true) {
                    if (MGLEncryption.AreEqual( guid, tempPAW.Token) == true) {
                        paw = tempPAW;
                        break;
                    }
                }
            }

            // random sleep to confuse on the checking if anyone is monitoring the timings!!
            Thread.Sleep(new Random().Next(0, 100));

            return paw;
        }



        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///      Remove widget
        /// </summary>
        public static void RemoveWidget(PasswordResetWidget paw) {

            int index = -1;
            int i = 0;
            foreach (PasswordResetWidget tempPAW in Widgets) {
                if (tempPAW.UserID == paw.UserID) {
                    index = i;
                    break;
                }
                i++;
            }

            if (index >= 0) {
                lock (PasswordReset.Widgets) {
                    Widgets.RemoveAt(index);
                }
            }
        }

    }


    //---------------------------------------------------------------------------------------------------------------------------------------------------------------
    internal class PasswordResetWidget {

        //------------------------------------------------------------------------------------------------------------------------------------------------------------
        public PasswordResetWidget() {

        }

        //------------------------------------------------------------------------------------------------------------------------------------------------------------
        public PasswordResetWidget(int userID, StringBuilder token, DateTime timeStamp) {
            this.userID = userID;
            this.token = token;
            this.timeStamp = timeStamp;
        }

        //------------------------------------------------------------------------------------------------------------------------------------------------------------
        private int userID = 0;
        public int UserID {
            get { return userID; }
            set { userID = value; }
        }
        //------------------------------------------------------------------------------------------------------------------------------------------------------------
        private StringBuilder token = new StringBuilder();
        public StringBuilder Token {
            get { return token; }
            set { token = value; }
        }
        //------------------------------------------------------------------------------------------------------------------------------------------------------------
        private DateTime timeStamp = DateTimeInformation.NullDate;
        public DateTime TimeStamp {
            get { return timeStamp; }
            set { timeStamp = value; }
        }


    }

}
