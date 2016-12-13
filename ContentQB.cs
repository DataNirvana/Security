using System;
using System.Collections.Generic;
using System.Text;

namespace MGL.Security
{
    public abstract class ContentQB
    {
        #region Static Methods

        internal static string GetInsertContentItemsFromSrcTblSql(string contentTable,
            MGL.Security.ContentType contentType)
        {
            StringBuilder builder = new StringBuilder();

            builder.Append("INSERT INTO ");
            builder.Append(contentTable);
            builder.Append(" (FeatureValue, Description, FeatureName) ");

            string selectContentItemsSql = ContentQB.GetSelectContentItemFromSrcTblSql(contentType);
            builder.Append(selectContentItemsSql);

            builder.Append(" GROUP BY " + contentType.ContentSrcIDCol);
            builder.Append(";");

            return builder.ToString();
        }

        internal static string GetInsertNewContentItemsFromSrcTblSql(string contentTable,
            MGL.Security.ContentType contentType)
        {
            StringBuilder builder = new StringBuilder();

            builder.Append("INSERT INTO ");
            builder.Append(contentTable);
            builder.Append(" (FeatureValue, Description, FeatureName) ");

            string selectContentItemsSql = ContentQB.GetSelectNewContentItemsFromSrcTblSql(contentType);
            builder.Append(selectContentItemsSql);

            builder.Append(" GROUP BY " + contentType.ContentSrcIDCol);
            builder.Append(";");

            return builder.ToString();
        }

        internal static string GetDeleteOldContentItemsFromSrcTblSql(string contentTable,
            MGL.Security.ContentType contentType)
        {
            StringBuilder builder = new StringBuilder();

// e.g           DELETE c.*
//FROM security_content c LEFT OUTER JOIN dl_themes s ON
//c.FeatureValue = s.dlt_ID
//WHERE c.FeatureName = 'THEME'
//AND s.dlt_ID IS NULL;

            builder.Append("DELETE c.* FROM ");
            builder.Append(contentTable);
            builder.Append(" c LEFT OUTER JOIN ");

            if (contentType.TypeOfContent != SecureRequestContext.ContentType.STAT_LAYER)
            {
                builder.Append(contentType.ContentSourceTable);
            }
            else
            {   // The active layers will always be in dl_layers, even if the security_content_type
                // specifices a different ContentSourceTable in order to display layers descriptions with their layer group name as a prefix

                builder.Append("dl_layers");
            }

            builder.Append(" s ");
            builder.Append(" ON c.FeatureValue = s.");
            builder.Append(contentType.ContentSrcIDCol);
            builder.Append(" WHERE c.FeatureName = '");
            builder.Append(contentType.TypeOfContent.ToString());
            builder.Append("' AND s.");
            builder.Append(contentType.ContentSrcIDCol);
            builder.Append(" IS NULL ");

            builder.Append(";");

            return builder.ToString();
        }

        internal static string GetDeleteOutdatedContentXrefs(string contentTable, string contentsXrefTable)
        {
            StringBuilder builder = new StringBuilder();

            builder.Append("DELETE x.* FROM ");
            builder.Append(contentsXrefTable);
            builder.Append(" x LEFT OUTER JOIN ");
            builder.Append(contentTable);
            builder.Append(" c ");
            builder.Append(" ON x.FeatureID = c.ID ");
            builder.Append(" WHERE ");
            builder.Append(" c.ID IS NULL");

            builder.Append(";");

            return builder.ToString();
        }

        internal static string GetSelectNewContentItemsFromSrcTblSql(MGL.Security.ContentType contentType)
        {
            StringBuilder sql = new StringBuilder();

            sql.Append("SELECT ");

            sql.Append(contentType.ContentSrcIDCol + " as ContentItemID,");

            if (contentType.TypeOfContent == SecureRequestContext.ContentType.THEME)
            {
                sql.Append("CONCAT(ifnull(" + contentType.ContentSrcParentNameCol + @", ''), CONVERT(IF(!ISNULL(" + contentType.ContentSrcParentNameCol + @"),' - ',''),CHAR), " + contentType.ContentSrcNameCol + @") as ContentItemName, '");
            }
            else
            {
                sql.Append(contentType.ContentSrcNameCol + " as ContentItemName, '");
            }

            sql.Append(contentType.TypeOfContent.ToString() + "' as ContentTypeName ");

            sql.Append(" FROM ");

            sql.Append(contentType.ContentSourceTable);

            sql.Append(" WHERE " + contentType.ContentSrcIDCol + @" NOT IN (SELECT FeatureValue FROM " + BaseSecurityOperations.tnContent + " WHERE FeatureName='" + contentType.TypeOfContent.ToString() + "') ");

            return sql.ToString();
        }

        internal static string GetSelectContentItemFromSrcTblSql(MGL.Security.ContentType contentType)
        {
            StringBuilder sql = new StringBuilder();

            sql.Append("SELECT ");

            sql.Append(contentType.ContentSrcIDCol + " as ContentItemID,");

            if (contentType.TypeOfContent == SecureRequestContext.ContentType.THEME)
            {
                sql.Append("CONCAT(ifnull(" + contentType.ContentSrcParentNameCol + @", ''), CONVERT(IF(!ISNULL(" + contentType.ContentSrcParentNameCol + @"),' - ',''),CHAR), " + contentType.ContentSrcNameCol + @") as ContentItemName, '");
            }
            else
            {
                sql.Append(contentType.ContentSrcNameCol + " as ContentItemName, '");
            }

            sql.Append(contentType.TypeOfContent.ToString() + "' as ContentTypeName ");

            sql.Append(" FROM ");
            sql.Append(contentType.ContentSourceTable);

            return sql.ToString();
        }

        internal static string GetSelectContentTypesSql()
        {
            return GetSelectContentTypesSql(null);
        }

         /// <summary>
        /// Create a SQL to get the Content Type objects from database.
        /// </summary>
        /// <param name="id">If ID is supplied, will get SQL for that ID, otherwise will create a SQL to get all contents</param>
        /// <returns></returns>
        internal static string GetSelectContentTypesSql(string id)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("SELECT ");
            sql.Append(CONTENT_ID_COL + ",");
            sql.Append(CONTENT_ENUMVAL_COL + ",");
            sql.Append(CONTENT_DISPLAYVAL_COL + ",");
            sql.Append(CONTENT_SRC_TBL_COL + ",");
            sql.Append(CONTENT_ITEM_IDCOL_NAME + ",");
            sql.Append(CONTENT_ITEM_NAMECOL_NAME + ",");
            sql.Append(CONTENT_ITEM_PARENTNAMECOL_NAME);
            sql.Append(" FROM ");
            sql.Append(CONTENT_TYPE_TBLE_NAME);
            if (id != null && id != string.Empty)
            {
                sql.Append(" WHERE ");
                sql.Append(CONTENT_ID_COL);
                sql.Append(" = ");
                sql.Append(id);
            }
            sql.Append(" ORDER BY ");
            sql.Append(CONTENT_DISPLAYVAL_COL);
            sql.Append(";");
            return sql.ToString();
        }




        internal static string GetSelectContentItemsSQL(MGL.Security.ContentType contentType,
            List<int> contentsIds)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("SELECT ");
            string orderClause = " ORDER BY ";
            string nameSelectCols = "";

            if (contentType.ContentSrcParentNameCol != null && contentType.ContentSrcParentNameCol != "")
            {
                nameSelectCols = contentType.ContentSrcParentNameCol + "," + contentType.ContentSrcNameCol;
                orderClause += contentType.ContentSrcParentNameCol + "," + contentType.ContentSrcNameCol;
            }
            else
            {
                orderClause += contentType.ContentSrcNameCol;
                nameSelectCols = contentType.ContentSrcNameCol;
            }
            sql.Append(contentType.ContentSrcIDCol + ",");
            if (contentType.TypeOfContent == SecureRequestContext.ContentType.THEME)
            {
                sql.Append(ContentQB.THEME_PARENT_ID_COL + ", ");
            }

            sql.Append(nameSelectCols);
            sql.Append(" FROM ");
            sql.Append(contentType.ContentSourceTable);

            if (contentsIds != null && contentsIds.Count > 0)
            {
                string idList = "(";
                bool first = true;
                foreach (int id in contentsIds)
                {
                    if (!first)
                    {
                        idList += ",";
                    }
                    idList += id.ToString();
                    first = false;
                }
                idList += ")";
                sql.Append(" WHERE ");
                sql.Append(contentType.ContentSrcIDCol + " IN ");
                sql.Append(idList);
            }
            sql.Append(orderClause);
            sql.Append(";");
            return sql.ToString();
        }


        internal static string GetAssignContentsToGroupSql(int groupID, int contentId)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("INSERT INTO ");
            sql.Append(GROUP_CONTENT_XREF_TBL);
            sql.Append("(");
            sql.Append(GroupQB.GROUP_ID_COL_XREFTBL + "," + GroupQB.GROUP_CONTENT_FEATUREID_COL);
            sql.Append(")");
            sql.Append("VALUES (");
            sql.Append(groupID);
            sql.Append(",");
            sql.Append(contentId);
            sql.Append(");");
            return sql.ToString();
        }

        internal static string GetUnAssignContentsToGroupSql(int groupID, int contentId)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("DELETE FROM ");
            sql.Append(GROUP_CONTENT_XREF_TBL);
            sql.Append(" WHERE ");
            sql.Append(GroupQB.GROUP_ID_COL_XREFTBL);
            sql.Append(" = " + groupID);
            sql.Append(" AND ");
            sql.Append(GroupQB.GROUP_CONTENT_FEATUREID_COL);
            sql.Append(" = " + contentId);
            sql.Append(";");
            return sql.ToString();
        }


        internal static string GetSelectContentIDsForContentFeaturesSql(List<int> contentsFeatureValues, string typeOfContent)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("SELECT " + CONTENT_ID_COL);
            sql.Append(" FROM ");
            sql.Append(CONTENT_SECURITY_TBL);

            if (contentsFeatureValues != null && contentsFeatureValues.Count > 0)
            {
                sql.Append(" WHERE ");
                string idList = "(";
                bool first = true;
                foreach (int id in contentsFeatureValues)
                {
                    if (!first)
                    {
                        idList += ",";
                    }
                    idList += id.ToString();
                    first = false;
                }
                idList += ")";

                sql.Append(GroupQB.GROUP_CONTENT_FEATUREVALUE_COL + " IN ");
                sql.Append(idList);
            }
            sql.Append(" AND ");
            sql.Append(GroupQB.GROUP_CONTENT_FEATURENAME_COL + " = '");
            sql.Append(typeOfContent);
            sql.Append("';");
            return sql.ToString();
        }

        internal static string GetSelectGetThemeParentChildIDsSql(List<int> contentIDs,
            MGL.Security.ContentType contentType)
        {
            bool isSelectChildContentID = true;
            return GetParentContentIDs(contentType, contentIDs, isSelectChildContentID);
        }

        internal static string GetParentContentIDs(MGL.Security.ContentType contentType, List<int> contentIDs)
        {
            bool isSelectChildContentID = false;
            return GetParentContentIDs(contentType, contentIDs, isSelectChildContentID);
        }

        internal static string GetParentContentIDs(MGL.Security.ContentType contentType,
            List<int> contentIDs, bool isSelectChildContentID)
        {
            StringBuilder sql = new StringBuilder();

            sql.Append("SELECT pc.ID ");

            if (isSelectChildContentID)
            {
                sql.Append(", c.ID ");
            }

            sql.Append(" FROM ");
            sql.Append(contentType.ContentSourceTable);
            sql.Append(" t, ");
            sql.Append(BaseSecurityOperations.tnContent);
            sql.Append(" c, ");
            sql.Append(BaseSecurityOperations.tnContent);
            sql.Append(" pc ");

            if (contentIDs != null && contentIDs.Count > 0)
            {
                string idList = "(";
                bool first = true;
                foreach (int id in contentIDs)
                {
                    if (!first)
                    {
                        idList += ",";
                    }
                    idList += id.ToString();
                    first = false;
                }
                idList += ")";

                sql.Append(" WHERE c.ID ");
                sql.Append(" IN ");
                sql.Append(idList);
            }

            sql.Append(" AND t.");
            sql.Append(THEME_PARENT_ID_COL);
            sql.Append(" <> -1 ");

            sql.Append(" AND c.FeatureName = 'THEME' AND ");
            sql.Append(" c.FeatureValue = t.dlt_ID AND ");
            sql.Append(" t.Dlt_ID <> -1 AND ");
            sql.Append(" pc.FeatureName = 'THEME' AND ");
            sql.Append(" pc.FeatureValue = t." + THEME_PARENT_ID_COL);

            sql.Append(" GROUP BY pc.ID");
            if (isSelectChildContentID)
            {
                sql.Append(", c.ID");
            }

            sql.Append(";");

            return sql.ToString();
        }

        #endregion

        #region !--- Static Vars ---!
        public static readonly string CONTENT_TYPE_TBLE_NAME = "security_content_types";
        public static readonly string CONTENT_ID_COL = "ID";
        public static readonly string CONTENT_ENUMVAL_COL = "Content_Enum_Value";
        public static readonly string CONTENT_DISPLAYVAL_COL = "Content_Display_Value";

        public static readonly string CONTENT_SRC_TBL_COL = "Content_SourceTableName";
        public static readonly string CONTENT_ITEM_IDCOL_NAME = "Content_ID_ColName";
        public static readonly string CONTENT_ITEM_NAMECOL_NAME = "Content_NameCol_Name";
        public static readonly string CONTENT_ITEM_PARENTNAMECOL_NAME = "Content_ParentNameCol_Name";
        public static readonly string THEME_PARENT_ID_COL = "dlt_ParentID";

        public static readonly string GROUP_CONTENT_XREF_TBL = BaseSecurityOperations.tnXrefGroupsContent;
        public static readonly string CONTENT_SECURITY_TBL = BaseSecurityOperations.tnContent;

        #endregion

    }
}
