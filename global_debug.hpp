#ifndef _GLOBAL_DEBUG_CONSTANT_HPP_
#define _GLOBAL_DEBUG_CONSTANT_HPP_

const static int SHOW_PROGRESS = 1;
const static int SHOW_SHARE_DETAIL = 2;
const static int SHOW_COMMUNICATION = 4;
const static int SHOW_TIME_LOG = 8;
const static int SHOW_ALL = SHOW_PROGRESS | SHOW_SHARE_DETAIL | SHOW_COMMUNICATION;
const static int LOG_LEVEL = 0; 

const static bool REPLICATED_INPUT_DEBUG = false;

const static int SEMI_RING_SHARE_PROCESS = 1;
const static int REP3SHARE_PROCESS = 2;
const static int SEMI3_RING_SHARE_PROCESS = 4;
const static int BUILDING_SHARE_PROCESS = 0;

const static int SHOW_DOTPROD_PROCESS = 1;
const static int DOTPROD_LOG_LEVEL = 0;

const static int SHOW_BIT_PROCESS = 1;
const static int SHOW_BIT_DETAIL = 2;
const static int BIT_LOG_LEVEL = 0;

const static int SHOW_INPUT_PROCESS = 1;
const static int SHOW_INPUT_DETAIL = 2;
const static int INPUT_LOG_LEVEL = 0;


const static int PROTOCOL_PROCESS = 1;
const static int PROTOCOL_LOG_LEVEL = 0;

const static int TRUNC_PROCESS = 1;
const static int TRUNC_DETAIL = 2;
const static int TRUNC_LOG_LEVEL = 0;


#endif