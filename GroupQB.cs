using System;
using System.Collections.Generic;
using System.Text;
using MGL.Data.DataUtilities;

namespace MGL.Security
{
    /// <summary>
    /// Creates queries for interacting with Group related data.
    /// </summary>
    public abstract class GroupQB
    {
        #region Static Methods

        internal static string GetDeleteUserFromAllGroupsSql(int userID)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("DELETE FROM ");
            sql.Append(GROUP_USER_XREF_TBL);
            sql.Append(" WHERE ");
            sql.Append(USER_ID_COL);
            sql.Append(" = " + userID);
            sql.Append(";");
            return sql.ToString();
        }

        internal static string GetAssignGroupForUserSql(int userID, int groupID)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("INSERT INTO ");
            sql.Append(GROUP_USER_XREF_TBL);
            sql.Append("(");
            sql.Append(GROUP_ID_COL_XREFTBL + "," + USER_ID_COL);
            sql.Append(")");
            sql.Append("VALUES (");
            sql.Append(groupID);
            sql.Append(",");
            sql.Append(userID);
            sql.Append(");");
            return sql.ToString();
        }

        internal static string GetUnAssignGroupForUserSql(int userID, int groupID)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("DELETE FROM ");
            sql.Append(GROUP_USER_XREF_TBL);
            sql.Append(" WHERE ");
            sql.Append(GROUP_ID_COL_XREFTBL);
            sql.Append(" = " + groupID);
            sql.Append(" AND ");
            sql.Append(USER_ID_COL);
            sql.Append(" = " + userID);
            sql.Append(";");
            return sql.ToString();
        }

        internal static string GetAssignFunctionsToGroupSql(int groupID, int functionId)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("INSERT INTO ");
            sql.Append(GROUP_FUNCTION_XREF_TBL);
            sql.Append("(");
            sql.Append(GROUP_ID_COL_XREFTBL + "," + GROUP_FUNCTION_FEATUREID_COL);
            sql.Append(")");
            sql.Append("VALUES (");
            sql.Append(groupID);
            sql.Append(",");
            sql.Append(functionId);
            sql.Append(");");
            return sql.ToString();
        }

        internal static string GetUnAssignFunctionsToGroupSql(int groupID, int functionId)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("DELETE FROM ");
            sql.Append(GROUP_FUNCTION_XREF_TBL);
            sql.Append(" WHERE ");
            sql.Append(GROUP_ID_COL_XREFTBL);
            sql.Append(" = " + groupID);
            sql.Append(" AND ");
            sql.Append(GROUP_FUNCTION_FEATUREID_COL);
            sql.Append(" = " + functionId);
            sql.Append(";");
            return sql.ToString();
        }

        internal static string GetCheckIfAGroupISPresentSql(string groupName)
        {
            return "SELECT " + GROUP_NAME_COL + " FROM " + GROUP_TBLE_NAME + " WHERE " + GROUP_NAME_COL + " = '" + groupName + "';";
        }

        internal static string GetSelectDefaultGroupIdsSql()
        {
            return "SELECT " + GROUP_ID_COL_GROUPTBL + " FROM " + GROUP_TBLE_NAME + " WHERE " + GROUP_DEFAULT_COL + " = 1;";

        }

        internal static string GetInsertGroupSql(MGL.DomainModel.MGGroup groupToAdd)
        {
            string cleanGroupName = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, groupToAdd.Name);
            string cleanGroupDesc = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, groupToAdd.Description); ;

            StringBuilder sql = new StringBuilder();
            sql.Append("INSERT INTO ");
            sql.Append(GROUP_TBLE_NAME);
            sql.Append("(");
            sql.Append(GROUP_NAME_COL + "," + GROUP_DESC_COL + "," + GROUP_DEFAULT_COL);
            sql.Append(")");
            sql.Append("VALUES ('");
            sql.Append(cleanGroupName);
            sql.Append("','");
            sql.Append(cleanGroupDesc);
            sql.Append("',");
            sql.Append(groupToAdd.IsDefault);
            sql.Append(");");

            return sql.ToString();
        }

        internal static string GetEditGroupSql(MGL.DomainModel.MGGroup newGroup)
        {
            string cleanGroupName = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, newGroup.Name);
            string cleanGroupDesc = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, newGroup.Description); ;

            StringBuilder sql = new StringBuilder();
            sql.Append("UPDATE ");
            sql.Append(GROUP_TBLE_NAME);
            sql.Append(" SET ");
            sql.Append(GROUP_NAME_COL + "='" + cleanGroupName + "',");
            sql.Append(GROUP_DESC_COL + "='" + cleanGroupDesc + "',");
            sql.Append(GROUP_DEFAULT_COL + "=" + newGroup.IsDefault);
            sql.Append(" WHERE ");
            sql.Append(GROUP_ID_COL_GROUPTBL + "=" + newGroup.ID);
            sql.Append(";");
            return sql.ToString();
        }


        internal static string GetSelectGroupContentPermissionSql(int groupID, GroupAdministration.AssociationTypes associationType)
        {
            StringBuilder sql = new StringBuilder();

            string selectColsContentTable = "C.FeatureName, C.FeatureValue FROM " + CONTENT_TBLE_NAME + " C ";

            if (associationType == GroupAdministration.AssociationTypes.Assign)
            {
                sql.Append("SELECT X." + GROUP_ID_COL_XREFTBL + ", ");
                sql.Append(selectColsContentTable);
                sql.Append(",");
                sql.Append(GROUP_CONTENT_XREF_TBL + " X ");
                sql.Append("WHERE ");
                sql.Append("X." + GROUP_CONTENT_FEATUREID_COL + " = C.ID ");
                sql.Append("AND X.GroupID = " + groupID);

            }
            else
            {
                sql.Append("SELECT " + groupID + " as GroupID,");
                sql.Append(selectColsContentTable);
                sql.Append("WHERE C.ID NOT IN");
                sql.Append("(");
                sql.Append(" SELECT X." + GROUP_CONTENT_FEATUREID_COL);
                sql.Append(" FROM " + GROUP_CONTENT_XREF_TBL + " X");
                if (associationType == GroupAdministration.AssociationTypes.UnAssign)
                {
                    sql.Append(" WHERE X.GroupID = " + groupID);
                }
                sql.Append(")");
            }

            sql.Append(" GROUP BY C.FeatureName, C.FeatureValue");
            sql.Append(";");

            return sql.ToString();
        }

        internal static string GetSelectFunctionDescriptionSql()
        {
            StringBuilder sql = new StringBuilder();

            sql.Append("SELECT F.FeatureName, F.Description FROM " + FUNCTION_TBLE_NAME);
            sql.Append(" F GROUP BY F.FeatureName ORDER BY F.Description;");
            return sql.ToString();
        }


        internal static string GetSelectGroupFunctionPermissionSql(int groupID, bool includeIDCol, bool includeDescCol, GroupAdministration.AssociationTypes associationType)
        {
            StringBuilder sql = new StringBuilder();

            string idCol = String.Empty;
            string descCol = String.Empty;
            string selectColsFunctionTable = string.Empty;
            string orderByCol = "F.FeatureValue";

            if (includeIDCol){
                idCol = ",F.ID";
            }
            if (includeDescCol){
                descCol = ",F.Description";
                orderByCol = "F.Description";
            }

            selectColsFunctionTable = "F.FeatureName,F.FeatureValue" + idCol + descCol + " FROM " + FUNCTION_TBLE_NAME + " F ";

            if (associationType == GroupAdministration.AssociationTypes.Assign)
            {
                sql.Append("SELECT X." + GROUP_ID_COL_XREFTBL + ", ");
                sql.Append(selectColsFunctionTable);
                sql.Append(",");
                sql.Append(GROUP_FUNCTION_XREF_TBL + " X ");
                sql.Append("WHERE ");
                sql.Append("X." + GROUP_FUNCTION_FEATUREID_COL + " = F.ID ");
                sql.Append("AND X.GroupID = " + groupID);

            }
            else
            {
                sql.Append("SELECT " + groupID + " as GroupID,");
                sql.Append(selectColsFunctionTable);
                sql.Append("WHERE F.ID NOT IN");
                sql.Append("(");
                sql.Append("SELECT X." + GROUP_FUNCTION_FEATUREID_COL);
                sql.Append(" FROM " + GROUP_FUNCTION_XREF_TBL + " X");
                if (associationType == GroupAdministration.AssociationTypes.UnAssign)
                {
                    sql.Append(" WHERE X.GroupID = " + groupID);
                }
                sql.Append(")");
            }

            sql.Append(" GROUP BY F.FeatureName, F.FeatureValue");

            sql.Append(" ORDER BY ");
            sql.Append(orderByCol);
            sql.Append(";");
            return sql.ToString();
        }

        internal static string GetSelectGroupDisplayPermissionSql(int groupID, bool includeIDCol, bool includeDescCol, GroupAdministration.AssociationTypes associationType)
        {
            StringBuilder sql = new StringBuilder();

            string idCol = String.Empty;
            string descCol = String.Empty;
            string selectColsDisplayTable = string.Empty;

            string orderByCol = "D.FeatureValue";
            if (includeIDCol)
            {
                idCol = ",D.ID";
            }
            if (includeDescCol)
            {
                descCol = ",D.Description";
                orderByCol = "D.Description";
            }

            selectColsDisplayTable = "D.FeatureName,D.FeatureValue" + idCol + descCol + " FROM " + DISPLAY_TBLE_NAME + " D ";

            if (associationType == GroupAdministration.AssociationTypes.Assign)
            {
                sql.Append("SELECT X." + GROUP_ID_COL_XREFTBL + ", ");
                sql.Append(selectColsDisplayTable);
                sql.Append(",");
                sql.Append(GROUP_DISPLAY_XREF_TBL + " X ");
                sql.Append("WHERE ");
                sql.Append("X." + GROUP_DISPLAY_FEATUREID_COL + " = D.ID ");
                sql.Append("AND X.GroupID = " + groupID);

            }
            else
            {
                sql.Append("SELECT " + groupID + " as GroupID,");
                sql.Append(selectColsDisplayTable);
                sql.Append("WHERE D.ID NOT IN");
                sql.Append("(");
                sql.Append("SELECT X." + GROUP_DISPLAY_FEATUREID_COL);
                sql.Append(" FROM " + GROUP_DISPLAY_XREF_TBL + " X");
                if (associationType == GroupAdministration.AssociationTypes.UnAssign)
                {
                    sql.Append(" WHERE X.GroupID = " + groupID);
                }
                sql.Append(")");
            }

            sql.Append(" GROUP BY D.FeatureName, D.FeatureValue");

            sql.Append(" ORDER BY ");
            sql.Append(orderByCol);
            sql.Append(";");
            return sql.ToString();
        }

        internal static string GetAssignDisplayToGroupSql(int groupID, int displayID)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("INSERT INTO ");
            sql.Append(GROUP_DISPLAY_XREF_TBL);
            sql.Append("(");
            sql.Append(GROUP_ID_COL_XREFTBL + "," + GROUP_DISPLAY_FEATUREID_COL);
            sql.Append(")");
            sql.Append("VALUES (");
            sql.Append(groupID);
            sql.Append(",");
            sql.Append(displayID);
            sql.Append(");");
            return sql.ToString();
        }

        internal static string GetUnAssignDisplayToGroupSql(int groupID, int displayID)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("DELETE FROM ");
            sql.Append(GROUP_DISPLAY_XREF_TBL);
            sql.Append(" WHERE ");
            sql.Append(GROUP_ID_COL_XREFTBL);
            sql.Append(" = " + groupID);
            sql.Append(" AND ");
            sql.Append(GROUP_DISPLAY_FEATUREID_COL);
            sql.Append(" = " + displayID);
            sql.Append(";");
            return sql.ToString();
        }

        internal static string GetDelteGroupSql(int groupID, string tableName, bool isMainTable)
        {
            StringBuilder sql = new StringBuilder();
            string idColName = "";

            sql.Append("DELETE FROM ");
            sql.Append(tableName);
            sql.Append(" WHERE ");

            if (isMainTable)
            {
                idColName = GROUP_ID_COL_GROUPTBL;
            }
            else
            {
                idColName = GROUP_ID_COL_XREFTBL;
            }

            sql.Append(idColName);
            sql.Append(" = " + groupID);
            sql.Append(";");
            return sql.ToString();
        }

        internal static string GetAssignGroupToContentsSql(List<int> groupIds, List<int> contentIds)
        {
            StringBuilder sql = new StringBuilder();
            sql.Append("INSERT INTO ");
            sql.Append(GROUP_CONTENT_XREF_TBL);
            sql.Append("(");
            sql.Append(GROUP_ID_COL_XREFTBL + "," + GROUP_CONTENT_FEATUREID_COL);
            sql.Append(")");
            sql.Append("VALUES ");

            string idList = "";
            bool first = true;
            foreach (int groupId in groupIds)
            {
                if (contentIds != null && contentIds.Count > 0)
                {
                    foreach (int id in contentIds)
                    {
                        if (!first)
                        {
                            idList += ",";
                        }
                        idList += "(";
                        idList += groupId;
                        idList += ",";
                        idList += id.ToString();
                        idList += ")";
                        first = false;
                    }
                }
            }
            sql.Append(idList);
            sql.Append(";");
            return sql.ToString();
        }



        internal static string GetSelectUsersForAGroupSql(int groupID, string filterString, GroupAdministration.AssociationTypes associationType)
        {
            StringBuilder sql = new StringBuilder();
            string selectFromUser = "U." + USER_ID_GENERAL_COL + ",U." + USER_NAME_COL + ",U." + USER_EMAIL_COL + ",U." + USER_JOBTITLE_COL + " FROM " + USER_TBLE_NAME + " U ";


            sql.Append("SELECT ");
            sql.Append(selectFromUser);

            filterString = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, filterString);
            //USE SQL INJECTION for search string

            string filterSQL = " WHERE ";
            if (filterString != null && filterString != string.Empty)
            {
                filterSQL += "(U." + USER_NAME_COL + " like '%" + filterString + "%' OR ";
                filterSQL += "U." + USER_EMAIL_COL + " like '%" + filterString + "%' OR ";
                filterSQL += "U." + USER_JOBTITLE_COL + " like '%" + filterString + "%')";
                filterSQL += " AND ";

            }

            if (associationType == GroupAdministration.AssociationTypes.Assign)
            {
                sql.Append(",");
                sql.Append(GROUP_USER_XREF_TBL + " X ");
                sql.Append(filterSQL);

                sql.Append("U." + USER_ID_GENERAL_COL + " = X." + USER_ID_COL);
                sql.Append(" AND ");
                sql.Append("X." + GROUP_ID_COL_XREFTBL + " = " + groupID);

            }
            else
            {
                sql.Append(filterSQL);
                sql.Append("U." + USER_ID_GENERAL_COL + " NOT IN");
                sql.Append("(");
                sql.Append("SELECT X." + USER_ID_COL);
                sql.Append(" FROM " + GROUP_USER_XREF_TBL + " X");
                if (associationType == GroupAdministration.AssociationTypes.UnAssign)
                {
                    sql.Append(" WHERE X." + GROUP_ID_COL_XREFTBL + " = " + groupID);
                }
                sql.Append(")");
            }
            sql.Append(" ORDER BY ");
            sql.Append("U." + USER_NAME_COL);
            sql.Append(";");
            return sql.ToString();
        }

        #endregion

        #region !--- Static Vars ---!
        public static readonly string GROUP_USER_XREF_TBL = "SECURITY_XREF_GROUP_USER";
        public static readonly string GROUP_ID_COL_XREFTBL = "GroupID";
        public static readonly string GROUP_NAME_COL = "GroupName";
        public static readonly string GROUP_DESC_COL = GroupOperations.DESC_COL_NAME;
        public static readonly string GROUP_DEFAULT_COL = GroupOperations.ISDEFAULT_COL_NAME;
        public static readonly string GROUP_TBLE_NAME = "Security_Groups";
        public static readonly string GROUP_ID_COL_GROUPTBL = "ID";


        public static readonly string USER_ID_COL = "UserID";
        public static readonly string GROUP_CONTENT_XREF_TBL = BaseSecurityOperations.tnXrefGroupsContent;
        public static readonly string CONTENT_TBLE_NAME = BaseSecurityOperations.tnContent;
        public static readonly string GROUP_CONTENT_FEATUREID_COL = "FeatureID";
        public static readonly string GROUP_CONTENT_FEATUREVALUE_COL = "FeatureValue";
        public static readonly string GROUP_CONTENT_FEATURENAME_COL = "FeatureName";

        public static readonly string GROUP_FUNCTION_XREF_TBL = BaseSecurityOperations.tnXrefGroupsFunctionality;
        public static readonly string FUNCTION_TBLE_NAME = BaseSecurityOperations.tnFunctionality;
        public static readonly string GROUP_FUNCTION_FEATUREID_COL = "FeatureID";


        public static readonly string GROUP_DISPLAY_XREF_TBL = BaseSecurityOperations.tnXrefGroupsDisplay;
        public static readonly string DISPLAY_TBLE_NAME = BaseSecurityOperations.tnDisplay;
        public static readonly string GROUP_DISPLAY_FEATUREID_COL = "FeatureID";

        public static readonly string USER_ID_GENERAL_COL = "ID";
        public static readonly string USER_NAME_COL = "UserName";
        public static readonly string USER_EMAIL_COL = "Email";
        public static readonly string USER_JOBTITLE_COL = "JobTitle";
        public static readonly string USER_TBLE_NAME = BaseSecurityOperations.tnUsers;


        #endregion











    }
}

