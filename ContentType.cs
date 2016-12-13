using System;
using System.Collections.Generic;
using System.Text;

namespace MGL.Security
{
    public class ContentType
    {

        #region !--- Properties ---!
        private int id;
        public int ID
        {
            get { return id; }
            set { id = value; }
        }
        private SecureRequestContext.ContentType typeOfContent;
        public SecureRequestContext.ContentType TypeOfContent
        {
            get { return typeOfContent; }
            set { typeOfContent = value; }
        }

        private string contentName;
        public string ContentName
        {
            get { return contentName; }
            set { contentName = value; }
        }

        private string contentSourceTable;
        public string ContentSourceTable
        {
            get { return contentSourceTable; }
            set { contentSourceTable = value; }
        }

        private string contentSrcIDCol;
        public string ContentSrcIDCol
        {
            get { return contentSrcIDCol; }
            set { contentSrcIDCol = value; }
        }

        private string contentSrcNameCol;
        public string ContentSrcNameCol
        {
            get { return contentSrcNameCol; }
            set { contentSrcNameCol = value; }
        }


        //This is special case for Themes as they have parents and parent name
        //has to be part of display name
        private string contentSrcParentNameCol;
        public string ContentSrcParentNameCol
        {
            get { return contentSrcParentNameCol; }
            set { contentSrcParentNameCol = value; }
        }



        #endregion

        #region !--- Constructor ---!
        public ContentType()
        {
            typeOfContent = SecureRequestContext.ContentType.UNKNOWN;
        }
        #endregion

    }
}
